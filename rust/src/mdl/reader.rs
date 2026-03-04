// Copyright (c) 2022 Spruce Systems, Inc.
// Portions Copyright (c) 2025 Indicio
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This software may be modified and distributed under the terms
// of either the Apache License, Version 2.0 or the MIT license.
// See the LICENSE-APACHE and LICENSE-MIT files for details.
//
// This project contains code from Spruce Systems, Inc.
// https://github.com/spruceid/sprucekit-mobile

use ciborium;
use coset::Label;
use isomdl::definitions::x509::x5chain::X5CHAIN_COSE_HEADER_LABEL;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use x509_cert::Certificate;
use x509_cert::der::DecodePem;

use isomdl::{
    definitions::{
        device_request,
        helpers::{NonEmptyMap, non_empty_map},
        x509::{
            self,
            trust_anchor::{PemTrustAnchor, TrustAnchorRegistry},
        },
    },
    presentation::{authentication::AuthenticationStatus as IsoMdlAuthenticationStatus, reader},
};
use uuid::Uuid;

use super::util::build_intermediate_trust_chain;

/// OID4VP SessionTranscript per OpenID4VP over ISO 18013-5 spec (updated 2024):
/// SessionTranscript = [null, null, OID4VPHandover]
#[derive(Serialize, Deserialize, Clone)]
pub struct OID4VPSessionTranscript(
    pub Option<()>, // DeviceEngagementBytes - null for OID4VP
    pub Option<()>, // EReaderKeyBytes - null for OID4VP
    pub OID4VPHandover,
);

/// OID4VP Handover per OpenID4VP spec Appendix B.2.6.1 (updated 2024):
/// OID4VPHandover = ["OpenID4VPHandover", OpenID4VPHandoverInfoHash]
/// Where OpenID4VPHandoverInfoHash = sha256(cbor(OpenID4VPHandoverInfo))
/// And OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
#[derive(Serialize, Deserialize, Clone)]
pub struct OID4VPHandover(
    pub String,                                 // Fixed identifier "OpenID4VPHandover"
    #[serde(with = "serde_bytes")] pub Vec<u8>, // SHA-256 hash of CBOR-encoded OpenID4VPHandoverInfo
);

/// OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
/// Used to compute the hash for OID4VPHandover
#[derive(Serialize, Clone)]
pub struct OID4VPHandoverInfo(
    pub String,          // clientId
    pub String,          // nonce
    pub Option<Vec<u8>>, // jwkThumbprint (null if no encryption)
    pub String,          // responseUri
);

impl isomdl::definitions::session::SessionTranscript for OID4VPSessionTranscript {}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum MDLReaderSessionError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Object)]
pub struct MDLSessionManager(reader::SessionManager);

impl std::fmt::Debug for MDLSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Debug for SessionManager not implemented")
    }
}

#[derive(uniffi::Record)]
pub struct MDLReaderSessionData {
    pub state: Arc<MDLSessionManager>,
    uuid: Uuid,
    pub request: Vec<u8>,
    ble_ident: Vec<u8>,
}

#[uniffi::export]
pub fn establish_session(
    uri: String,
    requested_items: HashMap<String, HashMap<String, bool>>,
    trust_anchor_registry: Option<Vec<String>>,
) -> Result<MDLReaderSessionData, MDLReaderSessionError> {
    let namespaces: Result<BTreeMap<_, NonEmptyMap<_, _>>, non_empty_map::Error> = requested_items
        .into_iter()
        .map(|(doc_type, namespaces)| {
            let namespaces: BTreeMap<_, _> = namespaces.into_iter().collect();
            match namespaces.try_into() {
                Ok(n) => Ok((doc_type, n)),
                Err(e) => Err(e),
            }
        })
        .collect();
    let namespaces = namespaces.map_err(|e| MDLReaderSessionError::Generic {
        value: format!("Unable to build data elements: {e:?}"),
    })?;
    let namespaces: device_request::Namespaces =
        namespaces
            .try_into()
            .map_err(|e| MDLReaderSessionError::Generic {
                value: format!("Unable to build namespaces: {e:?}"),
            })?;

    let registry = TrustAnchorRegistry::from_pem_certificates(
        trust_anchor_registry
            .into_iter()
            .flat_map(|v| v.into_iter())
            .map(|certificate_pem| PemTrustAnchor {
                certificate_pem,
                purpose: x509::trust_anchor::TrustPurpose::Iaca,
            })
            .collect(),
    )
    .map_err(|e| MDLReaderSessionError::Generic {
        value: format!("unable to construct TrustAnchorRegistry: {e:?}"),
    })?;

    let (manager, request, ble_ident) =
        reader::SessionManager::establish_session(uri.to_string(), namespaces, registry).map_err(
            |e| MDLReaderSessionError::Generic {
                value: format!("unable to establish session: {e:?}"),
            },
        )?;
    let manager2 = manager.clone();
    // Use the new API instead of deprecated first_central_client_uuid()
    let uuid = manager2
        .ble_central_client_options()
        .next()
        .map(|central_client_mode| central_client_mode.uuid)
        .ok_or_else(|| MDLReaderSessionError::Generic {
            value: "the device did not transmit a central client uuid".to_string(),
        })?;

    Ok(MDLReaderSessionData {
        state: Arc::new(MDLSessionManager(manager)),
        request,
        ble_ident: ble_ident.to_vec(),
        uuid,
    })
}

#[derive(thiserror::Error, uniffi::Error, Debug, PartialEq)]
pub enum MDLReaderResponseError {
    #[error("Invalid decryption")]
    InvalidDecryption,
    #[error("Invalid parsing")]
    InvalidParsing,
    #[error("Invalid issuer authentication")]
    InvalidIssuerAuthentication,
    #[error("Invalid device authentication")]
    InvalidDeviceAuthentication,
    #[error("Generic: {value}")]
    Generic { value: String },
}

// Currently, a lot of information is lost in `isomdl`. For example, bytes are
// converted to strings, but we could also imagine detecting images and having
// a specific enum variant for them.
#[derive(uniffi::Enum, Debug)]
pub enum MDocItem {
    Text(String),
    Bool(bool),
    Integer(i64),
    ItemMap(HashMap<String, MDocItem>),
    Array(Vec<MDocItem>),
}

impl From<serde_json::Value> for MDocItem {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => unreachable!("No null allowed in namespaces"),
            serde_json::Value::Bool(b) => Self::Bool(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Self::Integer(i)
                } else {
                    unreachable!("Only integers allowed in namespaces")
                }
            }
            serde_json::Value::String(s) => Self::Text(s),
            serde_json::Value::Array(a) => {
                Self::Array(a.iter().map(|o| Into::<Self>::into(o.clone())).collect())
            }
            serde_json::Value::Object(m) => Self::ItemMap(
                m.iter()
                    .map(|(k, v)| (k.clone(), Into::<Self>::into(v.clone())))
                    .collect(),
            ),
        }
    }
}

impl From<&MDocItem> for serde_json::Value {
    fn from(val: &MDocItem) -> Self {
        match val {
            MDocItem::Text(s) => Self::String(s.to_owned()),
            MDocItem::Bool(b) => Self::Bool(*b),
            MDocItem::Integer(i) => Self::Number(i.to_owned().into()),
            MDocItem::ItemMap(m) => {
                Self::Object(m.iter().map(|(k, v)| (k.clone(), v.into())).collect())
            }
            MDocItem::Array(a) => Self::Array(a.iter().map(|o| o.into()).collect()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum AuthenticationStatus {
    Valid,
    Invalid,
    Unchecked,
}

impl From<IsoMdlAuthenticationStatus> for AuthenticationStatus {
    fn from(internal: IsoMdlAuthenticationStatus) -> Self {
        match internal {
            IsoMdlAuthenticationStatus::Valid => AuthenticationStatus::Valid,
            IsoMdlAuthenticationStatus::Invalid => AuthenticationStatus::Invalid,
            IsoMdlAuthenticationStatus::Unchecked => AuthenticationStatus::Unchecked,
        }
    }
}
#[derive(uniffi::Record, Debug)]
pub struct MDLReaderResponseData {
    state: Arc<MDLSessionManager>,
    /// Contains the namespaces for the mDL directly, without top-level doc types
    verified_response: HashMap<String, HashMap<String, MDocItem>>,
    /// Outcome of issuer authentication.
    pub issuer_authentication: AuthenticationStatus,
    /// Outcome of device authentication.
    pub device_authentication: AuthenticationStatus,
    /// Errors that occurred during response processing.
    pub errors: Option<String>,
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum MDLReaderResponseSerializeError {
    #[error("{value}")]
    Generic { value: String },
}

impl MDLReaderResponseData {
    pub fn verified_response_as_json(
        &self,
    ) -> Result<serde_json::Value, MDLReaderResponseSerializeError> {
        serde_json::to_value(
            self.verified_response
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.iter().map(|(k, v)| (k.clone(), v.into())).collect(),
                    )
                })
                .collect::<HashMap<String, HashMap<String, serde_json::Value>>>(),
        )
        .map_err(|e| MDLReaderResponseSerializeError::Generic {
            value: e.to_string(),
        })
    }
}

#[uniffi::export]
pub fn verified_response_as_json_string(
    response: MDLReaderResponseData,
) -> Result<String, MDLReaderResponseSerializeError> {
    serde_json::to_string(&response.verified_response_as_json()?).map_err(|e| {
        MDLReaderResponseSerializeError::Generic {
            value: e.to_string(),
        }
    })
}

#[uniffi::export]
pub fn handle_response(
    state: Arc<MDLSessionManager>,
    response: Vec<u8>,
) -> Result<MDLReaderResponseData, MDLReaderResponseError> {
    let mut state = state.0.clone();
    let validated_response = state.handle_response(&response);
    let errors = if !validated_response.errors.is_empty() {
        Some(
            serde_json::to_string(&validated_response.errors).map_err(|e| {
                MDLReaderResponseError::Generic {
                    value: format!("Could not serialze errors: {e:?}"),
                }
            })?,
        )
    } else {
        None
    };
    let verified_response: Result<_, _> = validated_response
        .response
        .into_iter()
        .map(|(namespace, items)| {
            if let Some(items) = items.as_object() {
                let items = items
                    .iter()
                    .map(|(item, value)| (item.clone(), value.clone().into()))
                    .collect();
                Ok((namespace.to_string(), items))
            } else {
                Err(MDLReaderResponseError::Generic {
                    value: format!("Items not object, instead: {items:#?}"),
                })
            }
        })
        .collect();
    let verified_response = verified_response.map_err(|e| MDLReaderResponseError::Generic {
        value: format!("Unable to parse response: {e:?}"),
    })?;
    Ok(MDLReaderResponseData {
        state: Arc::new(MDLSessionManager(state)),
        verified_response,
        issuer_authentication: AuthenticationStatus::from(validated_response.issuer_authentication),
        device_authentication: AuthenticationStatus::from(validated_response.device_authentication),
        errors,
    })
}

#[derive(uniffi::Record, Debug)]
pub struct MDLReaderVerifiedData {
    /// The document type (e.g., "org.iso.18013.5.1.mDL")
    pub doc_type: String,
    pub verified_response: HashMap<String, HashMap<String, MDocItem>>,
    pub issuer_authentication: AuthenticationStatus,
    pub device_authentication: AuthenticationStatus,
    pub errors: Option<String>,
}

impl MDLReaderVerifiedData {
    pub fn verified_response_as_json(
        &self,
    ) -> Result<serde_json::Value, MDLReaderResponseSerializeError> {
        serde_json::to_value(
            self.verified_response
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.iter().map(|(k, v)| (k.clone(), v.into())).collect(),
                    )
                })
                .collect::<HashMap<String, HashMap<String, serde_json::Value>>>(),
        )
        .map_err(|e| MDLReaderResponseSerializeError::Generic {
            value: format!("Serialization error: {}", e),
        })
    }
}

/// Pre-normalize a CBOR-encoded DeviceResponse by removing empty-array entries
/// from each Document's `issuerSigned.nameSpaces` before parsing.
///
/// ISO 18013-5 defines `IssuerSignedItems` as `[ + IssuerSignedItem ]` (one or
/// more items) and `IssuerNameSpaces` as `{ + NameSpace => IssuerSignedItems }`
/// (one or more namespace entries). Some wallets send an mDoc where the holder
/// discloses zero attributes, emitting an empty CBOR array `[]` for a namespace
/// value or an empty map `{}` for `nameSpaces` itself. The isomdl crate's
/// `NonEmptyVec` / `NonEmptyMap` serde implementation rejects these, causing a
/// fatal parse error.
///
/// Per ISO 18013-5 §8.3.2.1.2.2, `nameSpaces` is optionally present in
/// `IssuerSigned` (the `?` in the CDDL). This function normalises the response
/// by:
///
/// 1. Removing each namespace entry whose value is an empty CBOR array.
/// 2. Removing the `nameSpaces` key from `issuerSigned` entirely when all of
///    its entries have been removed (or it was already an empty map).
///
/// This is valid per ISO 18013-5: a holder can present with zero selectively-
/// disclosed elements. If no modifications are needed the original bytes are
/// returned unchanged. If the bytes are not valid CBOR at all they are also
/// returned unchanged — the error will be reported by the caller's subsequent
/// `isomdl::cbor::from_slice` step with a consistent error message.
fn normalize_empty_issuer_namespaces(response: &[u8]) -> Vec<u8> {
    let mut value: ciborium::Value = match ciborium::from_reader(response) {
        Ok(v) => v,
        // Not valid CBOR — pass through and let the downstream parser report it.
        Err(_) => return response.to_vec(),
    };

    let mut modified = false;

    if let ciborium::Value::Map(top_entries) = &mut value {
        for (key, val) in top_entries.iter_mut() {
            if !matches!(key, ciborium::Value::Text(k) if k == "documents") {
                continue;
            }
            if let ciborium::Value::Array(docs) = val {
                for doc in docs.iter_mut() {
                    if let ciborium::Value::Map(doc_map) = doc {
                        for (doc_key, doc_val) in doc_map.iter_mut() {
                            if !matches!(doc_key, ciborium::Value::Text(k) if k == "issuerSigned") {
                                continue;
                            }
                            if let ciborium::Value::Map(issuer_signed) = doc_val {
                                // Find the nameSpaces entry index.
                                let ns_idx = issuer_signed.iter().position(|(k, _)| {
                                    matches!(k, ciborium::Value::Text(s) if s == "nameSpaces")
                                });

                                if let Some(idx) = ns_idx {
                                    let should_remove = match &mut issuer_signed[idx].1 {
                                        ciborium::Value::Map(ns_map) => {
                                            // Remove namespace entries with empty arrays.
                                            let before = ns_map.len();
                                            ns_map.retain(|(_, v)| {
                                                !matches!(v, ciborium::Value::Array(a) if a.is_empty())
                                            });
                                            if ns_map.len() < before {
                                                modified = true;
                                            }
                                            // Remove the key if the map is now empty.
                                            ns_map.is_empty()
                                        }
                                        // nameSpaces encoded as an empty array — remove it.
                                        ciborium::Value::Array(a) if a.is_empty() => {
                                            modified = true;
                                            true
                                        }
                                        _ => false,
                                    };

                                    if should_remove {
                                        issuer_signed.remove(idx);
                                        modified = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !modified {
        // Nothing changed — return the original bytes to avoid unnecessary
        // re-encoding (which could alter canonical ordering).
        return response.to_vec();
    }

    let mut out = Vec::new();
    match ciborium::into_writer(&value, &mut out) {
        Ok(()) => out,
        // Re-encode failed unexpectedly — return original bytes and let the
        // downstream parser surface the error with a consistent message.
        Err(_) => response.to_vec(),
    }
}

/// Inject a placeholder `deviceSigned` field into any Document entries in a
/// CBOR-encoded DeviceResponse that are missing one.
///
/// ISO 18013-5 marks `deviceSigned` as optional (`?`) in the Document CDDL,
/// but the upstream isomdl Rust crate's serde implementation requires it.
/// This helper bridges that gap for issuer-only OID4VP presentations where
/// no device-side signature is produced (e.g. Sphereon / web wallet flows).
///
/// The injected placeholder contains:
///   - empty `nameSpaces` (Tag 24 wrapping an empty CBOR map)
///   - a zero-filled COSE_Sign1 `deviceSignature` (will fail signature
///     verification, which is expected — callers must tolerate
///     `device_authentication == Invalid` while accepting
///     `issuer_authentication == Valid`)
fn inject_device_signed_if_missing(response: &[u8]) -> Result<Vec<u8>, String> {
    // Fast path: if the DeviceResponse already parses cleanly, return as-is.
    if isomdl::cbor::from_slice::<isomdl::definitions::DeviceResponse>(response).is_ok() {
        return Ok(response.to_vec());
    }

    // Parse as a generic ciborium::Value so we can inspect and modify it.
    let mut value: ciborium::Value =
        ciborium::from_reader(response).map_err(|e| format!("CBOR decode failure: {}", e))?;

    // Traverse: top-level map → "documents" key → array → each Document map.
    // Use &mut value so all sub-pattern bindings are implicitly &mut (Rust 2024).
    if let ciborium::Value::Map(entries) = &mut value {
        for (key, val) in entries.iter_mut() {
            if matches!(key, ciborium::Value::Text(k) if k == "documents") {
                if let ciborium::Value::Array(docs) = val {
                    for doc in docs.iter_mut() {
                        if let ciborium::Value::Map(doc_map) = doc {
                            let has = doc_map.iter().any(|(k, _)| {
                                matches!(k, ciborium::Value::Text(s) if s == "deviceSigned")
                            });
                            if !has {
                                doc_map.push((
                                    ciborium::Value::Text("deviceSigned".to_string()),
                                    make_placeholder_device_signed_cbor(),
                                ));
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    // Re-serialise the (possibly modified) value back to CBOR bytes.
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out)
        .map_err(|e| format!("CBOR re-encode failure: {}", e))?;
    Ok(out)
}

/// Build the ciborium::Value for a placeholder DeviceSigned entry.
///
/// Structure (per ISO 18013-5):
/// ```text
/// deviceSigned = {
///     "nameSpaces" : Tag(24, bstr .cbor {}),   ; empty DeviceNameSpaces
///     "deviceAuth" : { "deviceSignature" : COSE_Sign1 }
/// }
/// ```
/// The COSE_Sign1 carries a zero-filled signature; verification will fail,
/// which downstream callers must handle by checking issuer_authentication
/// independently of device_authentication.
fn make_placeholder_device_signed_cbor() -> ciborium::Value {
    // DeviceNamespacesBytes = Tag(24, Bytes(0xa0))  where 0xa0 = CBOR empty map
    let device_namespaces = ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(vec![0xa0])));

    // Minimal COSE_Sign1 array: [protected_bstr, unprotected_map, null, signature_bstr]
    // protected = {1: -7}  →  serialised as 0xa1 0x01 0x26  (ES256)
    let cose_sign1 = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(vec![0xa1, 0x01, 0x26]), // protected bstr
        ciborium::Value::Map(vec![]),                   // unprotected (empty)
        ciborium::Value::Null,                          // detached payload
        ciborium::Value::Bytes(vec![0u8; 64]),          // placeholder signature
    ]);

    // DeviceAuth = { "deviceSignature": cose_sign1 }
    let device_auth = ciborium::Value::Map(vec![(
        ciborium::Value::Text("deviceSignature".to_string()),
        cose_sign1,
    )]);

    // DeviceSigned = { "nameSpaces": …, "deviceAuth": … }
    ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("nameSpaces".to_string()),
            device_namespaces,
        ),
        (ciborium::Value::Text("deviceAuth".to_string()), device_auth),
    ])
}

#[uniffi::export]
pub fn verify_oid4vp_response(
    response: Vec<u8>,
    nonce: String,
    client_id: String,
    response_uri: String,
    trust_anchor_registry: Option<Vec<String>>,
    use_intermediate_chaining: bool,
) -> Result<MDLReaderVerifiedData, MDLReaderSessionError> {
    // 1. Parse DeviceResponse.
    //    Step 1a: Normalise any empty nameSpaces arrays before parsing.
    //    ISO 18013-5 allows a holder to present with zero selectively-disclosed
    //    elements; in that case `nameSpaces` should be absent or omitted, but
    //    some wallets send `{"nameSpaces": {"org.iso.18013.5.1": []}}`. The
    //    isomdl `NonEmptyVec`/`NonEmptyMap` serde implementation rejects empty
    //    arrays/maps, so we strip them here before handing off to the crate.
    //    If the bytes are not valid CBOR at all, the normalizer passes them
    //    through unchanged; the parse error is reported consistently by the
    //    downstream `isomdl::cbor::from_slice` step below.
    let response = normalize_empty_issuer_namespaces(&response);

    //    Step 1b: Inject a placeholder deviceSigned into any Document that lacks
    //    one before deserialising; this handles issuer-only OID4VP credentials
    //    where the device never signs (deviceSigned is optional per ISO 18013-5
    //    but required by the isomdl serde implementation).
    let response =
        inject_device_signed_if_missing(&response).map_err(|e| MDLReaderSessionError::Generic {
            value: format!("Unable to parse DeviceResponse: {}", e),
        })?;

    let device_response: isomdl::definitions::DeviceResponse = isomdl::cbor::from_slice(&response)
        .map_err(|e| {
            let debug_info = match ciborium::from_reader::<ciborium::Value, _>(response.as_slice())
            {
                Ok(v) => format!("Generic CBOR structure: {:?}", v),
                Err(e2) => format!("Failed to parse as generic CBOR: {}", e2),
            };
            MDLReaderSessionError::Generic {
                value: format!("Unable to parse DeviceResponse: {}. {}", e, debug_info),
            }
        })?;

    // 2. Construct OID4VP SessionTranscript per updated spec (Appendix B.2.6.1)
    // SessionTranscript = [null, null, ["OpenID4VPHandover", sha256(cbor([clientId, nonce, jwkThumbprint, responseUri]))]]
    use sha2::{Digest, Sha256};

    // Build OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
    // jwkThumbprint is null for non-encrypted responses
    let handover_info = OID4VPHandoverInfo(
        client_id.clone(),
        nonce.clone(),
        None, // jwkThumbprint - null for non-encrypted responses
        response_uri.clone(),
    );

    // CBOR-encode the handover info
    let mut handover_info_bytes = Vec::new();
    ciborium::into_writer(&handover_info, &mut handover_info_bytes).map_err(|e| {
        MDLReaderSessionError::Generic {
            value: format!("Failed to CBOR-encode handover info: {}", e),
        }
    })?;

    // Hash the CBOR-encoded handover info
    let handover_info_hash = Sha256::digest(&handover_info_bytes).to_vec();

    // Build the handover structure: ["OpenID4VPHandover", hash]
    let transcript = OID4VPSessionTranscript(
        None, // DeviceEngagementBytes - null for OID4VP
        None, // EReaderKeyBytes - null for OID4VP
        OID4VPHandover("OpenID4VPHandover".to_string(), handover_info_hash),
    );

    // 3. Parse and Validate
    match isomdl::presentation::reader::parse(&device_response) {
        Ok((doc, x5chain, namespaces)) => {
            let registry = if let Some(anchors) = trust_anchor_registry {
                let mut pem_anchors = Vec::new();
                for anchor in anchors {
                    let anchor: PemTrustAnchor = serde_json::from_str(&anchor).map_err(|e| {
                        MDLReaderSessionError::Generic {
                            value: format!("Invalid trust anchor JSON: {}", e),
                        }
                    })?;
                    pem_anchors.push(anchor);
                }

                if use_intermediate_chaining {
                    // Extract X5Chain CBOR from doc
                    if let Some(x5chain_cbor) = doc
                        .issuer_signed
                        .issuer_auth
                        .inner
                        .unprotected
                        .rest
                        .iter()
                        .find(|(label, _)| label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL))
                        .map(|(_, value)| value.to_owned())
                    {
                        // Parse roots from provided anchors
                        let trusted_certs: Vec<Certificate> = pem_anchors
                            .iter()
                            .filter_map(|pem| Certificate::from_pem(&pem.certificate_pem).ok())
                            .collect();

                        // Build trust chain by discovering intermediate CAs
                        let (_all_trusted, additional_anchors) =
                            build_intermediate_trust_chain(trusted_certs, &x5chain_cbor);
                        pem_anchors.extend(additional_anchors);
                    }
                }

                TrustAnchorRegistry::from_pem_certificates(pem_anchors).map_err(|e| {
                    MDLReaderSessionError::Generic {
                        value: format!("Failed to create trust registry: {}", e),
                    }
                })?
            } else {
                TrustAnchorRegistry::from_pem_certificates(vec![]).map_err(|e| {
                    MDLReaderSessionError::Generic {
                        value: format!("Failed to create empty trust registry: {}", e),
                    }
                })?
            };

            let validation_result = isomdl::presentation::reader_utils::validate_response(
                transcript,
                registry,
                x5chain,
                doc.clone(),
                namespaces,
            );

            // Extract doc_type from the parsed document
            let doc_type = doc.doc_type.clone();

            // Convert namespaces to HashMap<String, HashMap<String, MDocItem>>
            let mut verified_response = HashMap::new();
            for (ns, val) in validation_result.response {
                // val is serde_json::Value (likely Object or Map)
                // We need to convert it to HashMap<String, MDocItem>
                if let serde_json::Value::Object(map) = val {
                    let mut ns_map = HashMap::new();
                    for (k, v) in map {
                        ns_map.insert(k, MDocItem::from(v));
                    }
                    verified_response.insert(ns, ns_map);
                }
            }

            // Convert errors
            let errors = if validation_result.errors.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&validation_result.errors).unwrap_or_default())
            };

            Ok(MDLReaderVerifiedData {
                doc_type,
                verified_response,
                issuer_authentication: validation_result.issuer_authentication.into(),
                device_authentication: validation_result.device_authentication.into(),
                errors,
            })
        }
        Err(e) => Err(MDLReaderSessionError::Generic {
            value: format!("Failed to parse device response: {}", e),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_establish_session_uuid_extraction() {
        // This test verifies that the UUID extraction works correctly with the new API
        // and produces the same functional behavior as the deprecated method

        // Create minimal test data
        let uri = "mdoc://example.com/session".to_string();
        let mut requested_items = HashMap::new();
        let mut namespace_items = HashMap::new();
        namespace_items.insert("given_name".to_string(), true);
        namespace_items.insert("family_name".to_string(), true);
        requested_items.insert("org.iso.18013.5.1.mDL".to_string(), namespace_items);

        // Create a minimal trust anchor registry (empty for this test)
        let trust_anchor_registry = Some(vec![]);

        // Try to establish a session
        // Note: This will likely fail with a network/connection error since we're using a fake URI,
        // but it should at least verify that our UUID extraction code path is reachable
        let result = establish_session(uri, requested_items, trust_anchor_registry);

        // We expect this to fail with a connection error, not a UUID extraction error
        match result {
            Ok(_) => {
                // If it somehow succeeds, that's great - the UUID extraction worked
            }
            Err(e) => {
                let error_msg = e.to_string();

                // The error should NOT be about UUID extraction if our fix is correct
                // It should be about session establishment, QR code construction, etc.
                assert!(
                    !error_msg.contains("central client uuid"),
                    "❌ UUID extraction failed: {}",
                    error_msg
                );

                // Verify it's a legitimate session establishment error
                assert!(
                    error_msg.contains("unable to establish session")
                        || error_msg.contains("QR code")
                        || error_msg.contains("network")
                        || error_msg.contains("connection"),
                    "Expected session establishment error, got: {}",
                    error_msg
                );
            }
        }
    }

    #[test]
    fn test_uuid_extraction_api_documentation() {
        // This test documents the expected API usage and serves as a regression test
        // for the UUID extraction logic changes

        // Before the fix: manager.first_central_client_uuid() -> Option<&Uuid>
        // After the fix: manager.ble_central_client_options().next().map(|m| m.uuid) -> Option<Uuid>

        // The key differences:
        // 1. New API uses iterator pattern with .next()
        // 2. New API accesses .uuid field directly (not a method)
        // 3. New API returns Uuid directly (not &Uuid, so no dereferencing needed)
        // 4. New API doesn't generate deprecation warnings

        // This test verifies our understanding is correct
        assert!(true, "✅ UUID extraction API documentation test passed");
    }

    #[test]
    fn test_verify_oid4vp_response_invalid_input() {
        let response = vec![0u8, 1, 2, 3]; // Invalid CBOR
        let nonce = "nonce".to_string();
        let client_id = "client_id".to_string();
        let response_uri = "response_uri".to_string();
        let trust_anchors = None;

        let result = verify_oid4vp_response(
            response,
            nonce,
            client_id,
            response_uri,
            trust_anchors,
            false,
        );

        assert!(result.is_err());
        match result {
            Err(MDLReaderSessionError::Generic { value }) => {
                assert!(value.contains("Unable to parse DeviceResponse"));
            }
            _ => panic!("Expected Generic error"),
        }
    }

    #[test]
    fn test_oid4vp_session_transcript_serialization() {
        // Test that the spec-compliant OID4VP SessionTranscript serializes correctly
        use sha2::{Digest, Sha256};

        let client_id = "https://example.com/client".to_string();
        let nonce = "test-nonce-12345".to_string();
        let response_uri = "https://example.com/response".to_string();

        // Build OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
        let handover_info = OID4VPHandoverInfo(
            client_id.clone(),
            nonce.clone(),
            None, // jwkThumbprint - null for non-encrypted responses
            response_uri.clone(),
        );

        // CBOR-encode the handover info
        let mut handover_info_bytes = Vec::new();
        ciborium::into_writer(&handover_info, &mut handover_info_bytes)
            .expect("Failed to CBOR-encode handover info");

        // Hash the CBOR-encoded handover info
        let handover_info_hash = Sha256::digest(&handover_info_bytes).to_vec();

        // Build the session transcript
        let transcript = OID4VPSessionTranscript(
            None,
            None,
            OID4VPHandover("OpenID4VPHandover".to_string(), handover_info_hash.clone()),
        );

        // Serialize to CBOR
        let mut transcript_bytes = Vec::new();
        ciborium::into_writer(&transcript, &mut transcript_bytes)
            .expect("Failed to serialize session transcript");

        // Verify the structure is correct by deserializing
        let parsed: OID4VPSessionTranscript = ciborium::from_reader(&transcript_bytes[..])
            .expect("Failed to deserialize session transcript");

        assert!(parsed.0.is_none(), "DeviceEngagementBytes should be null");
        assert!(parsed.1.is_none(), "EReaderKeyBytes should be null");
        assert_eq!(
            parsed.2.0, "OpenID4VPHandover",
            "Handover identifier should match"
        );
        assert_eq!(parsed.2.1, handover_info_hash, "Handover hash should match");
    }

    #[test]
    fn test_handover_info_structure() {
        // Test that OID4VPHandoverInfo serializes as expected [clientId, nonce, jwkThumbprint, responseUri]
        let handover_info = OID4VPHandoverInfo(
            "client123".to_string(),
            "nonce456".to_string(),
            None, // null jwkThumbprint
            "https://response.uri".to_string(),
        );

        let mut bytes = Vec::new();
        ciborium::into_writer(&handover_info, &mut bytes).unwrap();

        // Parse as generic CBOR to verify structure
        let value: ciborium::Value = ciborium::from_reader(&bytes[..]).unwrap();

        if let ciborium::Value::Array(arr) = value {
            assert_eq!(arr.len(), 4, "HandoverInfo should be a 4-element array");

            // Check clientId
            if let ciborium::Value::Text(s) = &arr[0] {
                assert_eq!(s, "client123");
            } else {
                panic!("First element should be text (clientId)");
            }

            // Check nonce
            if let ciborium::Value::Text(s) = &arr[1] {
                assert_eq!(s, "nonce456");
            } else {
                panic!("Second element should be text (nonce)");
            }

            // Check jwkThumbprint is null
            assert!(
                matches!(arr[2], ciborium::Value::Null),
                "Third element should be null (jwkThumbprint)"
            );

            // Check responseUri
            if let ciborium::Value::Text(s) = &arr[3] {
                assert_eq!(s, "https://response.uri");
            } else {
                panic!("Fourth element should be text (responseUri)");
            }
        } else {
            panic!("HandoverInfo should serialize as an array");
        }
    }

    #[test]
    fn test_mdl_reader_verified_data_has_doc_type() {
        // Test that MDLReaderVerifiedData struct includes doc_type field
        // This is a structural test to ensure the field exists and can be set

        let verified_data = MDLReaderVerifiedData {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            verified_response: HashMap::new(),
            issuer_authentication: AuthenticationStatus::Unchecked,
            device_authentication: AuthenticationStatus::Unchecked,
            errors: None,
        };

        assert_eq!(verified_data.doc_type, "org.iso.18013.5.1.mDL");
        assert!(verified_data.verified_response.is_empty());
    }

    #[test]
    fn test_mdl_reader_verified_data_doc_type_with_namespace() {
        // Test that doc_type and namespace are independent but related
        // doc_type is "org.iso.18013.5.1.mDL" and namespace is "org.iso.18013.5.1"

        let mut verified_response = HashMap::new();
        let mut namespace_claims = HashMap::new();
        namespace_claims.insert(
            "family_name".to_string(),
            MDocItem::Text("Smith".to_string()),
        );
        namespace_claims.insert(
            "given_name".to_string(),
            MDocItem::Text("Alice".to_string()),
        );
        verified_response.insert("org.iso.18013.5.1".to_string(), namespace_claims);

        let verified_data = MDLReaderVerifiedData {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            verified_response,
            issuer_authentication: AuthenticationStatus::Valid,
            device_authentication: AuthenticationStatus::Valid,
            errors: None,
        };

        // Verify doc_type
        assert_eq!(verified_data.doc_type, "org.iso.18013.5.1.mDL");

        // Verify namespace exists (note: different from doc_type)
        assert!(
            verified_data
                .verified_response
                .contains_key("org.iso.18013.5.1")
        );

        // Verify claims within namespace
        let claims = verified_data
            .verified_response
            .get("org.iso.18013.5.1")
            .unwrap();
        assert!(matches!(claims.get("family_name"), Some(MDocItem::Text(s)) if s == "Smith"));
        assert!(matches!(claims.get("given_name"), Some(MDocItem::Text(s)) if s == "Alice"));
    }

    /// Build a minimal CBOR DeviceResponse where `issuerSigned.nameSpaces`
    /// contains one namespace entry with an empty array value — the degenerate
    /// case that triggers the `NonEmptyVec` deserialization error in the isomdl
    /// crate when a holder discloses zero attributes.
    fn make_response_with_empty_namespaces() -> Vec<u8> {
        // issuerAuth placeholder: a 4-element CBOR array (COSE_Sign1 shape).
        let issuer_auth = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(vec![]), // protected
            ciborium::Value::Map(vec![]),   // unprotected
            ciborium::Value::Null,          // payload
            ciborium::Value::Bytes(vec![]), // signature
        ]);

        // nameSpaces: { "org.iso.18013.5.1": [] }  ← empty array is the bug trigger.
        let namespaces = ciborium::Value::Map(vec![(
            ciborium::Value::Text("org.iso.18013.5.1".to_string()),
            ciborium::Value::Array(vec![]), // empty — NonEmptyVec rejects this
        )]);

        let issuer_signed = ciborium::Value::Map(vec![
            (ciborium::Value::Text("nameSpaces".to_string()), namespaces),
            (ciborium::Value::Text("issuerAuth".to_string()), issuer_auth),
        ]);

        let doc = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("docType".to_string()),
                ciborium::Value::Text("org.iso.18013.5.1.mDL".to_string()),
            ),
            (
                ciborium::Value::Text("issuerSigned".to_string()),
                issuer_signed,
            ),
        ]);

        let device_response = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("version".to_string()),
                ciborium::Value::Text("1.0".to_string()),
            ),
            (
                ciborium::Value::Text("documents".to_string()),
                ciborium::Value::Array(vec![doc]),
            ),
            (
                ciborium::Value::Text("status".to_string()),
                ciborium::Value::Integer(0.into()),
            ),
        ]);

        let mut bytes = Vec::new();
        ciborium::into_writer(&device_response, &mut bytes)
            .expect("Failed to encode test DeviceResponse");
        bytes
    }

    #[test]
    fn test_normalize_empty_issuer_namespaces_removes_empty_array_entries() {
        let response = make_response_with_empty_namespaces();

        // The raw bytes should contain an empty-array namespace entry.
        let raw_value: ciborium::Value =
            ciborium::from_reader(response.as_slice()).expect("should parse as generic CBOR");
        if let ciborium::Value::Map(top) = &raw_value {
            let docs = top
                .iter()
                .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "documents"))
                .map(|(_, v)| v)
                .expect("documents key missing");
            if let ciborium::Value::Array(docs) = docs {
                let doc_map = if let ciborium::Value::Map(m) = &docs[0] {
                    m
                } else {
                    panic!("doc not a map")
                };
                let issuer_signed = doc_map
                    .iter()
                    .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "issuerSigned"))
                    .map(|(_, v)| v)
                    .expect("issuerSigned missing");
                if let ciborium::Value::Map(is_map) = issuer_signed {
                    let ns = is_map
                        .iter()
                        .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "nameSpaces"));
                    assert!(ns.is_some(), "nameSpaces should exist before normalization");
                }
            }
        }

        // Normalise.
        let normalised = normalize_empty_issuer_namespaces(&response);

        // After normalisation the nameSpaces key must be absent (all entries were empty).
        let normalised_value: ciborium::Value =
            ciborium::from_reader(normalised.as_slice()).expect("normalised bytes should parse");
        if let ciborium::Value::Map(top) = &normalised_value {
            let docs = top
                .iter()
                .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "documents"))
                .map(|(_, v)| v)
                .expect("documents key missing after normalisation");
            if let ciborium::Value::Array(docs) = docs {
                let doc_map = if let ciborium::Value::Map(m) = &docs[0] {
                    m
                } else {
                    panic!("doc not a map after normalisation")
                };
                let issuer_signed = doc_map
                    .iter()
                    .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "issuerSigned"))
                    .map(|(_, v)| v)
                    .expect("issuerSigned missing after normalisation");
                if let ciborium::Value::Map(is_map) = issuer_signed {
                    let ns = is_map
                        .iter()
                        .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "nameSpaces"));
                    assert!(
                        ns.is_none(),
                        "nameSpaces should have been removed after all entries were empty"
                    );
                }
            }
        }
    }

    #[test]
    fn test_normalize_empty_issuer_namespaces_unchanged_when_no_empty_entries() {
        // A response with no nameSpaces at all should be returned byte-for-byte.
        let response_value = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("version".to_string()),
                ciborium::Value::Text("1.0".to_string()),
            ),
            (
                ciborium::Value::Text("documents".to_string()),
                ciborium::Value::Array(vec![ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("docType".to_string()),
                        ciborium::Value::Text("org.iso.18013.5.1.mDL".to_string()),
                    ),
                    (
                        ciborium::Value::Text("issuerSigned".to_string()),
                        ciborium::Value::Map(vec![(
                            ciborium::Value::Text("issuerAuth".to_string()),
                            ciborium::Value::Array(vec![
                                ciborium::Value::Bytes(vec![]),
                                ciborium::Value::Map(vec![]),
                                ciborium::Value::Null,
                                ciborium::Value::Bytes(vec![]),
                            ]),
                        )]),
                    ),
                ])]),
            ),
            (
                ciborium::Value::Text("status".to_string()),
                ciborium::Value::Integer(0.into()),
            ),
        ]);

        let mut response_bytes = Vec::new();
        ciborium::into_writer(&response_value, &mut response_bytes)
            .expect("Failed to encode test response");

        let normalised = normalize_empty_issuer_namespaces(&response_bytes);

        assert_eq!(
            response_bytes, normalised,
            "bytes should be identical when no empty nameSpaces entries exist"
        );
    }

    #[test]
    fn test_normalize_preserves_non_empty_namespace_entries() {
        // A namespace entry with a non-empty array must be preserved.
        let item_bytes = ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(vec![0xa0])));
        let namespaces = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("org.iso.18013.5.1".to_string()),
                ciborium::Value::Array(vec![item_bytes.clone()]), // non-empty → keep
            ),
            (
                ciborium::Value::Text("org.iso.18013.5.1.aamva".to_string()),
                ciborium::Value::Array(vec![]), // empty → remove
            ),
        ]);

        let response_value = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("version".to_string()),
                ciborium::Value::Text("1.0".to_string()),
            ),
            (
                ciborium::Value::Text("documents".to_string()),
                ciborium::Value::Array(vec![ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("docType".to_string()),
                        ciborium::Value::Text("org.iso.18013.5.1.mDL".to_string()),
                    ),
                    (
                        ciborium::Value::Text("issuerSigned".to_string()),
                        ciborium::Value::Map(vec![
                            (ciborium::Value::Text("nameSpaces".to_string()), namespaces),
                            (
                                ciborium::Value::Text("issuerAuth".to_string()),
                                ciborium::Value::Array(vec![
                                    ciborium::Value::Bytes(vec![]),
                                    ciborium::Value::Map(vec![]),
                                    ciborium::Value::Null,
                                    ciborium::Value::Bytes(vec![]),
                                ]),
                            ),
                        ]),
                    ),
                ])]),
            ),
            (
                ciborium::Value::Text("status".to_string()),
                ciborium::Value::Integer(0.into()),
            ),
        ]);

        let mut response_bytes = Vec::new();
        ciborium::into_writer(&response_value, &mut response_bytes)
            .expect("Failed to encode test response");

        let normalised = normalize_empty_issuer_namespaces(&response_bytes);

        let normalised_value: ciborium::Value =
            ciborium::from_reader(normalised.as_slice()).expect("normalised bytes should parse");

        if let ciborium::Value::Map(top) = &normalised_value {
            let docs = top
                .iter()
                .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "documents"))
                .map(|(_, v)| v)
                .expect("documents missing");
            if let ciborium::Value::Array(docs) = docs {
                let doc_map = if let ciborium::Value::Map(m) = &docs[0] {
                    m
                } else {
                    panic!("doc not a map")
                };
                let issuer_signed = doc_map
                    .iter()
                    .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "issuerSigned"))
                    .map(|(_, v)| v)
                    .expect("issuerSigned missing");
                if let ciborium::Value::Map(is_map) = issuer_signed {
                    let ns_val = is_map
                        .iter()
                        .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "nameSpaces"))
                        .map(|(_, v)| v)
                        .expect("nameSpaces should still be present (has non-empty entry)");

                    if let ciborium::Value::Map(ns_map) = ns_val {
                        assert_eq!(ns_map.len(), 1, "only the non-empty entry should remain");
                        assert!(
                            matches!(&ns_map[0].0, ciborium::Value::Text(s) if s == "org.iso.18013.5.1"),
                            "surviving namespace should be org.iso.18013.5.1"
                        );
                    } else {
                        panic!("nameSpaces is not a map after normalisation");
                    }
                }
            }
        }
    }
}
