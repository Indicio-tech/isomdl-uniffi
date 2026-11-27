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

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::Cursor,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use base64::prelude::*;
use ciborium::Value;
use coset::{Label, iana};
use isomdl::{
    definitions::{
        CoseKey, DeviceKeyInfo, DigestAlgorithm, EC2Curve, EC2Y, IssuerSigned, Mso, ValidityInfo,
        helpers::{NonEmptyMap, Tag24},
        namespaces::{
            org_iso_18013_5_1::OrgIso1801351, org_iso_18013_5_1_aamva::OrgIso1801351Aamva,
        },
        traits::{FromJson, ToNamespaceMap},
        x509::{
            X5Chain,
            trust_anchor::{PemTrustAnchor, TrustAnchorRegistry, TrustPurpose},
            x5chain::X5CHAIN_COSE_HEADER_LABEL,
        },
    },
    issuance::mdoc::Builder,
    presentation::{Stringify, authentication::mdoc::issuer_authentication, device::Document},
};
use p256::{PublicKey, elliptic_curve::sec1::ToEncodedPoint};
use serde::Deserialize;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use x509_cert::Certificate;
use x509_cert::der::DecodePem;

use super::util::{build_intermediate_trust_chain, setup_certificate_chain};

uniffi::custom_newtype!(Namespace, String);
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
/// A namespace for mdoc data elements.
pub struct Namespace(String);

uniffi::custom_newtype!(KeyAlias, String);
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct KeyAlias(pub String);

#[derive(Debug, Clone, uniffi::Record)]
/// Simple representation of an mdoc data element.
pub struct Element {
    /// Name of the data element.
    pub identifier: String,
    /// JSON representation of the data element, missing if the value cannot be represented as JSON.
    pub value: Option<String>,
}

#[derive(uniffi::Object, Debug, Clone, Serialize, Deserialize)]
pub struct Mdoc {
    inner: Document,
    key_alias: KeyAlias,
}

#[uniffi::export]
impl Mdoc {
    #[uniffi::constructor]
    /// Construct a new MDoc from base64url-encoded IssuerSigned.
    pub fn new_from_base64url_encoded_issuer_signed(
        base64url_encoded_issuer_signed: String,
        key_alias: KeyAlias,
    ) -> Result<Arc<Self>, MdocInitError> {
        let issuer_signed = isomdl::cbor::from_slice(
            &BASE64_URL_SAFE_NO_PAD
                .decode(base64url_encoded_issuer_signed)
                .map_err(|_| MdocInitError::IssuerSignedBase64UrlDecoding)?,
        )
        .map_err(|_| MdocInitError::IssuerSignedCborDecoding)?;
        Self::new_from_issuer_signed(key_alias, issuer_signed)
    }

    #[uniffi::constructor]
    /// Compatibility feature: construct an MDoc from a
    /// [stringified spruceid/isomdl `Document`](https://github.com/spruceid/isomdl/blob/main/src/presentation/mod.rs#L100)
    pub fn from_stringified_document(
        stringified_document: String,
        key_alias: KeyAlias,
    ) -> Result<Arc<Self>, MdocInitError> {
        let inner = Document::parse(stringified_document)
            .map_err(|_| MdocInitError::DocumentUtf8Decoding)?;
        Ok(Arc::new(Self { inner, key_alias }))
    }

    #[uniffi::constructor]
    /// Parse an MDoc from a stringified document with a default key alias.
    /// This is a convenience method for parsing mdocs where the key alias is not critical.
    pub fn from_string(stringified_document: String) -> Result<Arc<Self>, MdocInitError> {
        let inner = Document::parse(stringified_document)
            .map_err(|_| MdocInitError::DocumentUtf8Decoding)?;
        let key_alias = KeyAlias("parsed".to_string());
        Ok(Arc::new(Self { inner, key_alias }))
    }

    #[uniffi::constructor]
    /// Construct a SpruceKit MDoc from a cbor-encoded
    /// [spruceid/isomdl `Document`](https://github.com/spruceid/isomdl/blob/main/src/presentation/device.rs#L145-L152)
    pub fn from_cbor_encoded_document(
        cbor_encoded_document: Vec<u8>,
        key_alias: KeyAlias,
    ) -> Result<Arc<Self>, MdocInitError> {
        let inner = isomdl::cbor::from_slice(&cbor_encoded_document)
            .map_err(|e| MdocInitError::DocumentCborDecoding(e.to_string()))?;
        Ok(Arc::new(Self { inner, key_alias }))
    }

    #[uniffi::constructor]
    pub fn create_and_sign(
        doc_type: String,
        namespaces: HashMap<String, HashMap<String, String>>,
        holder_jwk: String,
        iaca_cert_perm: String,
        iaca_key_perm: String,
        status_list: Option<String>,
    ) -> Result<Arc<Self>, MdocInitError> {
        let pub_key: PublicKey =
            PublicKey::from_jwk_str(&holder_jwk).map_err(|_e| MdocInitError::InvalidJwk)?;

        let namespaces = convert_namespaces_json(namespaces)?;
        let status_list = parse_status_json(status_list)?;
        let builder = prepare_builder(
            pub_key,
            namespaces,
            doc_type,
            status_list,
            default_validity_info(),
        )
        .map_err(|e| MdocInitError::GeneralConstructionError(format!("prepare_builder: {e}")))?;

        let (certificate, iaca_certs, signer) =
            setup_certificate_chain(iaca_cert_perm, iaca_key_perm, None).map_err(|e| {
                MdocInitError::GeneralConstructionError(format!("certificate chain: {e}"))
            })?;

        let mut x5chain_builder =
            X5Chain::builder()
                .with_certificate(certificate)
                .map_err(|e| {
                    MdocInitError::GeneralConstructionError(format!("x5chain certificate: {e}"))
                })?;

        for cert in iaca_certs {
            x5chain_builder = x5chain_builder.with_certificate(cert).map_err(|e| {
                MdocInitError::GeneralConstructionError(format!("x5chain intermediate: {e}"))
            })?;
        }

        let x5chain = x5chain_builder
            .build()
            .map_err(|e| MdocInitError::GeneralConstructionError(format!("x5chain build: {e}")))?;

        let mdoc = builder
            .issue::<p256::ecdsa::SigningKey, p256::ecdsa::Signature>(x5chain, signer)
            .map_err(|e| MdocInitError::GeneralConstructionError(format!("issue: {e}")))?;

        let namespaces = NonEmptyMap::maybe_new(
            mdoc.namespaces
                .into_inner()
                .into_iter()
                .map(|(namespace, elements)| {
                    let inner_map = NonEmptyMap::maybe_new(
                        elements
                            .into_inner()
                            .into_iter()
                            .map(|element| (element.as_ref().element_identifier.clone(), element))
                            .collect(),
                    )
                    .ok_or(MdocInitError::GeneralConstructionError(
                        "empty namespace elements".into(),
                    ))?;
                    Ok((namespace, inner_map))
                })
                .collect::<Result<_, MdocInitError>>()?,
        )
        .ok_or(MdocInitError::GeneralConstructionError(
            "empty namespaces".into(),
        ))?;

        let doc = Document {
            id: Default::default(),
            issuer_auth: mdoc.issuer_auth,
            mso: mdoc.mso,
            namespaces,
        };

        Ok(Arc::new(super::mdoc::Mdoc::new_from_parts(
            doc,
            KeyAlias(Uuid::new_v4().to_string()),
        )))
    }

    #[uniffi::constructor]
    pub fn create_and_sign_mdl(
        mdl_items: String,
        aamva_items: Option<String>,
        holder_jwk: String,
        iaca_cert_pem: String,
        iaca_key_pem: String,
        status_list: Option<String>,
    ) -> Result<Arc<Self>, MdocInitError> {
        let pub_key: PublicKey =
            PublicKey::from_jwk_str(&holder_jwk).map_err(|_e| MdocInitError::InvalidJwk)?;

        let mut namespaces = BTreeMap::new();

        // Parse mDL items
        let json_value: serde_json::Value = serde_json::from_str(&mdl_items).map_err(|e| {
            MdocInitError::GeneralConstructionError(format!("mdl_items JSON parse: {e}"))
        })?;
        let mdl_data = OrgIso1801351::from_json(&json_value)
            .map_err(|e| {
                MdocInitError::GeneralConstructionError(format!(
                    "mDL namespace parse (org.iso.18013.5.1): {e}"
                ))
            })?
            .to_ns_map();
        namespaces.insert("org.iso.18013.5.1".to_string(), mdl_data);

        // Parse AAMVA items if present
        if let Some(aamva_json) = aamva_items {
            let json_value: serde_json::Value = serde_json::from_str(&aamva_json).map_err(|e| {
                MdocInitError::GeneralConstructionError(format!("aamva JSON parse: {e}"))
            })?;
            let aamva_data = OrgIso1801351Aamva::from_json(&json_value)
                .map_err(|e| {
                    MdocInitError::GeneralConstructionError(format!("AAMVA namespace parse: {e}"))
                })?
                .to_ns_map();
            namespaces.insert("org.iso.18013.5.1.aamva".to_string(), aamva_data);
        }

        let doc_type = "org.iso.18013.5.1.mDL".to_string();

        let status_list = parse_status_json(status_list)?;
        let builder = prepare_builder(
            pub_key,
            namespaces,
            doc_type,
            status_list,
            default_validity_info(),
        )
        .map_err(|e| MdocInitError::GeneralConstructionError(format!("prepare_builder: {e}")))?;

        let (certificate, iaca_certs, signer) =
            setup_certificate_chain(iaca_cert_pem, iaca_key_pem, None).map_err(|e| {
                MdocInitError::GeneralConstructionError(format!("certificate chain: {e}"))
            })?;

        let mut x5chain_builder =
            X5Chain::builder()
                .with_certificate(certificate)
                .map_err(|e| {
                    MdocInitError::GeneralConstructionError(format!("x5chain certificate: {e}"))
                })?;

        for cert in iaca_certs {
            x5chain_builder = x5chain_builder.with_certificate(cert).map_err(|e| {
                MdocInitError::GeneralConstructionError(format!("x5chain intermediate: {e}"))
            })?;
        }

        let x5chain = x5chain_builder
            .build()
            .map_err(|e| MdocInitError::GeneralConstructionError(format!("x5chain build: {e}")))?;

        let mdoc = builder
            .issue::<p256::ecdsa::SigningKey, p256::ecdsa::Signature>(x5chain, signer)
            .map_err(|e| MdocInitError::GeneralConstructionError(format!("issue: {e}")))?;

        let namespaces = NonEmptyMap::maybe_new(
            mdoc.namespaces
                .into_inner()
                .into_iter()
                .map(|(namespace, elements)| {
                    let inner_map = NonEmptyMap::maybe_new(
                        elements
                            .into_inner()
                            .into_iter()
                            .map(|element| (element.as_ref().element_identifier.clone(), element))
                            .collect(),
                    )
                    .ok_or(MdocInitError::GeneralConstructionError(
                        "empty namespace elements".into(),
                    ))?;
                    Ok((namespace, inner_map))
                })
                .collect::<Result<_, MdocInitError>>()?,
        )
        .ok_or(MdocInitError::GeneralConstructionError(
            "empty namespaces".into(),
        ))?;

        let doc = Document {
            id: Default::default(),
            issuer_auth: mdoc.issuer_auth,
            mso: mdoc.mso,
            namespaces,
        };

        Ok(Arc::new(super::mdoc::Mdoc::new_from_parts(
            doc,
            KeyAlias(Uuid::new_v4().to_string()),
        )))
    }

    /// The local ID of this credential.
    pub fn id(&self) -> Uuid {
        self.inner.id
    }

    /// The document type of this mdoc, for example `org.iso.18013.5.1.mDL`.
    pub fn doctype(&self) -> String {
        self.inner.mso.doc_type.clone()
    }

    /// The status claim embedded in the MSO, as a JSON string, if any.
    pub fn status_list(&self) -> Option<String> {
        self.inner
            .mso
            .status
            .as_ref()
            .and_then(|v| serde_json::to_string(v).ok())
    }

    /// Simple representation of mdoc namespace and data elements for display in the UI.
    pub fn details(&self) -> HashMap<Namespace, Vec<Element>> {
        self.document()
            .namespaces
            .clone()
            .into_inner()
            .into_iter()
            .map(|(namespace, elements)| {
                (
                    Namespace(namespace),
                    elements
                        .into_inner()
                        .into_values()
                        .map(|tagged| {
                            let element = tagged.into_inner();
                            Element {
                                identifier: element.element_identifier,
                                value: serde_json::to_string_pretty(&element.element_value).ok(),
                            }
                        })
                        .collect(),
                )
            })
            .collect()
    }

    pub fn key_alias(&self) -> KeyAlias {
        self.key_alias.clone()
    }

    /// Serialize as JSON
    pub fn json(&self) -> Result<String, crate::mdl::mdoc::MdocEncodingError> {
        match serde_json::to_string(&self.inner) {
            Ok(it) => Ok(it),
            Err(_e) => Err(MdocEncodingError::SerializationError),
        }
    }

    /// Serialize to CBOR
    pub fn stringify(&self) -> Result<String, crate::mdl::mdoc::MdocEncodingError> {
        match self.inner.stringify() {
            Ok(it) => Ok(it),
            Err(_e) => Err(MdocEncodingError::SerializationError),
        }
    }

    /// Serialize as an ISO 18013-5 §8.3 compliant IssuerSigned structure (base64url, no padding).
    ///
    /// Unlike [`Mdoc::stringify`], which serializes the internal `Document` struct
    /// with snake_case CBOR keys (`issuer_auth`, `namespaces`), this method
    /// serializes an [`IssuerSigned`] value using the camelCase keys required
    /// by ISO 18013-5 §8.3 (`issuerAuth`, `nameSpaces`) and the correct
    /// map-of-lists namespace representation (`NonEmptyVec<IssuerSignedItemBytes>`).
    ///
    /// This is the correct format for use in OpenID4VCI mso_mdoc credential issuance
    /// and ISO 18013-5 presentation.
    pub fn issuer_signed_b64(&self) -> Result<String, MdocEncodingError> {
        use isomdl::definitions::helpers::NonEmptyVec;

        // Document.namespaces: NonEmptyMap<String, NonEmptyMap<ElementIdentifier, IssuerSignedItemBytes>>
        // IssuerSigned.namespaces: Option<NonEmptyMap<String, NonEmptyVec<IssuerSignedItemBytes>>>
        //
        // The element identifier is embedded in each IssuerSignedItem, so we drop
        // the map keys and collect just the values into a NonEmptyVec.
        let converted = self
            .inner
            .namespaces
            .clone()
            .into_inner()
            .into_iter()
            .map(|(ns, element_map)| {
                let items: Vec<_> = element_map.into_inner().into_values().collect();
                let vec =
                    NonEmptyVec::maybe_new(items).ok_or(MdocEncodingError::SerializationError)?;
                Ok((ns, vec))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>, MdocEncodingError>>()?;

        let issuer_signed = IssuerSigned {
            namespaces: NonEmptyMap::maybe_new(converted),
            issuer_auth: self.inner.issuer_auth.clone(),
        };

        let cbor_bytes = isomdl::cbor::to_vec(&issuer_signed)
            .map_err(|_| MdocEncodingError::SerializationError)?;
        Ok(BASE64_URL_SAFE_NO_PAD.encode(cbor_bytes))
    }

    /// Verify the issuer signature of this mdoc credential.
    ///
    /// This method extracts the X5Chain from the issuer_auth header, validates it
    /// against the provided trust anchors, and verifies the COSE_Sign1 signature.
    ///
    /// # Arguments
    /// * `trust_anchors` - Optional list of PEM-encoded trust anchor certificates.
    ///   If not provided, X5Chain validation is skipped but signature verification
    ///   is still performed using the certificate in the X5Chain.
    /// * `use_intermediate_chaining` - If true, the verifier will attempt to build a trust path
    ///   using intermediate certificates found in the X5Chain header. If false, only the
    ///   certificates explicitly provided in `trust_anchors` are trusted.
    ///
    /// # Returns
    /// * `Ok(IssuerVerificationResult)` - The verification result with verified status
    ///   and optional common name from the issuer certificate.
    /// * `Err(MdocVerificationError)` - If verification fails due to missing/invalid
    ///   X5Chain or signature verification failure.
    pub fn verify_issuer_signature(
        &self,
        trust_anchors: Option<Vec<String>>,
        use_intermediate_chaining: bool,
    ) -> Result<IssuerVerificationResult, MdocVerificationError> {
        // 1. Extract X5Chain from issuer_auth unprotected header
        let x5chain_cbor = self
            .inner
            .issuer_auth
            .inner
            .unprotected
            .rest
            .iter()
            .find(|(label, _)| label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL))
            .map(|(_, value)| value.to_owned())
            .ok_or(MdocVerificationError::X5ChainMissing)?;

        let x5chain = X5Chain::from_cbor(x5chain_cbor.clone())
            .map_err(|e| MdocVerificationError::X5ChainParsing(format!("{:?}", e)))?;

        // 2. Get the common name from the end-entity certificate
        let common_name = Some(x5chain.end_entity_common_name().to_string());

        // 3. If trust anchors are provided, validate the X5Chain against them
        if let Some(anchors) = trust_anchors.filter(|a| !a.is_empty()) {
            let mut pem_anchors: Vec<PemTrustAnchor> = anchors
                .iter()
                .map(|cert_pem| PemTrustAnchor {
                    certificate_pem: cert_pem.clone(),
                    purpose: TrustPurpose::Iaca,
                })
                .collect();

            if use_intermediate_chaining {
                // Parse roots from provided anchors
                let trusted_certs: Vec<Certificate> = anchors
                    .iter()
                    .filter_map(|pem| Certificate::from_pem(pem).ok())
                    .collect();

                // Build trust chain by discovering intermediate CAs
                let (_all_trusted, additional_anchors) =
                    build_intermediate_trust_chain(trusted_certs, &x5chain_cbor);
                pem_anchors.extend(additional_anchors);
            }

            let registry = TrustAnchorRegistry::from_pem_certificates(pem_anchors)
                .map_err(|e| MdocVerificationError::TrustAnchorRegistryError(format!("{:?}", e)))?; // Validate X5Chain against trust anchors using mDL validation rules
            // `&()` is isomdl's documented no-op RevocationFetcher ("use `&()` to
            // skip revocation checks"); it does not affect the X.509 chain/trust-anchor
            // validation performed here.
            let validation_errors = pollster::block_on(
                isomdl::definitions::x509::validation::ValidationRuleset::Mdl.validate(
                    &x5chain,
                    &registry,
                    &(),
                ),
            )
            .errors;

            if !validation_errors.is_empty() {
                return Err(MdocVerificationError::X5ChainValidationFailed(
                    validation_errors
                        .iter()
                        .map(|e| format!("{:?}", e))
                        .collect::<Vec<_>>()
                        .join(", "),
                ));
            }
        }

        // 4. Build IssuerSigned from the Document for verification
        // The issuer_authentication function expects IssuerSigned which contains
        // the issuer_auth (COSE_Sign1) and namespaces
        let namespaces_map = self
            .inner
            .namespaces
            .clone()
            .into_inner()
            .into_iter()
            .map(|(ns, elements)| {
                let inner_elements = elements
                    .into_inner()
                    .into_values()
                    .collect::<Vec<_>>()
                    .try_into()
                    .map_err(|_| {
                        MdocVerificationError::IssuerAuthFailed(
                            "Internal error: Empty inner namespace elements".to_string(),
                        )
                    })?;
                Ok((ns, inner_elements))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>, MdocVerificationError>>()?;

        let namespaces = namespaces_map.try_into().map_err(|_| {
            MdocVerificationError::IssuerAuthFailed(
                "Internal error: Empty namespaces map".to_string(),
            )
        })?;

        let issuer_signed = isomdl::definitions::IssuerSigned {
            namespaces: Some(namespaces),
            issuer_auth: self.inner.issuer_auth.clone(),
        };

        // 5. Verify issuer signature
        match issuer_authentication(x5chain, &issuer_signed) {
            Ok(_) => Ok(IssuerVerificationResult {
                verified: true,
                common_name,
                error: None,
            }),
            Err(e) => Err(MdocVerificationError::IssuerAuthFailed(format!("{:?}", e))),
        }
    }
}

impl Mdoc {
    pub(crate) fn document(&self) -> &Document {
        &self.inner
    }

    pub(crate) fn new_from_parts(inner: Document, key_alias: KeyAlias) -> Self {
        Self { inner, key_alias }
    }

    fn new_from_issuer_signed(
        key_alias: KeyAlias,
        IssuerSigned {
            namespaces,
            issuer_auth,
        }: IssuerSigned,
    ) -> Result<Arc<Self>, MdocInitError> {
        let namespaces = namespaces
            .ok_or(MdocInitError::NamespacesMissing)?
            .into_inner()
            .into_iter()
            .map(|(k, v)| {
                let m = v
                    .into_inner()
                    .into_iter()
                    .map(|i| (i.as_ref().element_identifier.clone(), i))
                    .collect::<BTreeMap<_, _>>()
                    .try_into()
                    .map_err(|_| {
                        MdocInitError::GeneralConstructionError(
                            "empty namespace elements in IssuerSigned".into(),
                        )
                    })?;
                Ok((k, m))
            })
            .collect::<Result<BTreeMap<_, _>, MdocInitError>>()?
            .try_into()
            .map_err(|_| {
                MdocInitError::GeneralConstructionError("empty namespaces in IssuerSigned".into())
            })?;

        let mso: Tag24<Mso> = isomdl::cbor::from_slice(
            issuer_auth
                .payload
                .as_ref()
                .ok_or(MdocInitError::IssuerAuthPayloadMissing)?,
        )
        .map_err(|_| MdocInitError::IssuerAuthPayloadDecoding)?;

        Ok(Arc::new(Self {
            key_alias,
            inner: Document {
                id: Uuid::new_v4(),
                issuer_auth,
                namespaces,
                mso: mso.into_inner(),
            },
        }))
    }
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum MdocInitError {
    #[error("failed to decode Document from CBOR: {0}")]
    DocumentCborDecoding(String),
    #[error("failed to decode base64url_encoded_issuer_signed from base64url-encoded bytes")]
    IssuerSignedBase64UrlDecoding,
    #[error("failed to decode IssuerSigned from CBOR")]
    IssuerSignedCborDecoding,
    #[error("IssuerAuth CoseSign1 has no payload")]
    IssuerAuthPayloadMissing,
    #[error("failed to decode IssuerAuth CoseSign1 payload as an MSO")]
    IssuerAuthPayloadDecoding,
    #[error("a key alias is required for an mdoc, and none was provided")]
    KeyAliasMissing,
    #[error("IssuerSigned did not contain namespaces")]
    NamespacesMissing,
    #[error("failed to decode Document from UTF-8 string")]
    DocumentUtf8Decoding,
    #[error("failed to parse JWK")]
    InvalidJwk,
    #[error("failed to construct mdoc: {0}")]
    GeneralConstructionError(String),
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum MdocEncodingError {
    #[error("failed to encode Document to CBOR")]
    DocumentCborEncoding,
    #[error("failed to serialize mdoc")]
    SerializationError,
}

/// Error type for issuer signature verification.
#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum MdocVerificationError {
    #[error("X5Chain header missing from issuer_auth")]
    X5ChainMissing,
    #[error("Failed to parse X5Chain: {0}")]
    X5ChainParsing(String),
    #[error("Failed to create trust anchor registry: {0}")]
    TrustAnchorRegistryError(String),
    #[error("X5Chain validation failed against trust anchors: {0}")]
    X5ChainValidationFailed(String),
    #[error("Issuer signature verification failed: {0}")]
    IssuerAuthFailed(String),
}

/// Result of issuer signature verification.
#[derive(Debug, Clone, uniffi::Record)]
pub struct IssuerVerificationResult {
    /// Whether the issuer signature was successfully verified.
    pub verified: bool,
    /// Common name from the issuer certificate, if available.
    pub common_name: Option<String>,
    /// Error message if verification failed.
    pub error: Option<String>,
}

/// A prepared (unsigned) mDoc, ready for external signing.
///
/// Created by [`PreparedMdoc::new()`]. Call [`signature_payload()`](Self::signature_payload)
/// to obtain the bytes that must be signed, then supply the signature and
/// certificate chain to [`complete()`](Self::complete) to produce the final
/// signed [`Mdoc`].
#[derive(uniffi::Object)]
pub struct PreparedMdoc {
    inner: std::sync::Mutex<Option<isomdl::issuance::mdoc::PreparedMdoc>>,
}

#[uniffi::export]
impl PreparedMdoc {
    /// Prepare an mDoc for external signing.
    ///
    /// The returned object holds the partially-constructed mDoc. Use
    /// [`signature_payload()`] to get the bytes that must be signed by the
    /// issuer key, then call [`complete()`] with the raw signature and
    /// PEM-encoded certificate chain to finalize the mDoc.
    ///
    /// `signature_algorithm` must be one of: `"ES256"`, `"ES384"`, `"ES512"`.
    /// `namespaces` maps namespace → (element_identifier → JSON-encoded value).
    #[uniffi::constructor]
    pub fn new(
        doc_type: String,
        namespaces: HashMap<String, HashMap<String, String>>,
        holder_jwk: String,
        signature_algorithm: String,
        status_list: Option<String>,
    ) -> Result<Arc<Self>, MdocInitError> {
        let pub_key: PublicKey =
            PublicKey::from_jwk_str(&holder_jwk).map_err(|_e| MdocInitError::InvalidJwk)?;

        let namespaces = convert_namespaces_json(namespaces)?;
        let status_list = parse_status_json(status_list)?;
        let builder = prepare_builder(
            pub_key,
            namespaces,
            doc_type,
            status_list,
            default_validity_info(),
        )
        .map_err(|e| MdocInitError::GeneralConstructionError(format!("prepare_builder: {e}")))?;

        let algorithm = parse_signature_algorithm(&signature_algorithm)?;
        let prepared = builder
            .prepare(algorithm)
            .map_err(|e| MdocInitError::GeneralConstructionError(format!("prepare: {e}")))?;

        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(Some(prepared)),
        }))
    }

    /// Prepare an mDL (`org.iso.18013.5.1.mDL`) document for external signing.
    ///
    /// Unlike [`PreparedMdoc::new()`], which uses a generic JSON→CBOR conversion,
    /// this constructor uses the ISO 18013-5 typed namespace builder
    /// (`OrgIso1801351`) to ensure correct CBOR field types (e.g. `birth_date`
    /// encoded as a CBOR `full-date`, not a plain text string).
    ///
    /// * `mdl_items` — JSON object string with mDL namespace elements.
    /// * `aamva_items` — Optional JSON object string with AAMVA namespace elements.
    /// * `holder_jwk` — P-256 JWK of the holder's device key.
    /// * `signature_algorithm` — one of `"ES256"`, `"ES384"`, `"ES512"`.
    #[uniffi::constructor]
    pub fn new_mdl(
        mdl_items: String,
        aamva_items: Option<String>,
        holder_jwk: String,
        signature_algorithm: String,
        status_list: Option<String>,
    ) -> Result<Arc<Self>, MdocInitError> {
        let pub_key: PublicKey =
            PublicKey::from_jwk_str(&holder_jwk).map_err(|_e| MdocInitError::InvalidJwk)?;

        let mut namespaces = BTreeMap::new();

        // Parse mDL items using the typed mDL parser (OrgIso1801351::from_json),
        // same as create_and_sign_mdl.  This ensures CBOR field types are correct
        // (e.g. birth_date as tdate rather than a plain text string).
        let json_value: serde_json::Value = serde_json::from_str(&mdl_items).map_err(|e| {
            MdocInitError::GeneralConstructionError(format!("mdl_items JSON parse: {e}"))
        })?;
        let mdl_data = OrgIso1801351::from_json(&json_value)
            .map_err(|e| {
                MdocInitError::GeneralConstructionError(format!(
                    "mDL namespace parse (org.iso.18013.5.1): {e}"
                ))
            })?
            .to_ns_map();
        namespaces.insert("org.iso.18013.5.1".to_string(), mdl_data);

        // Parse AAMVA items if present
        if let Some(aamva_json) = aamva_items {
            let json_value: serde_json::Value = serde_json::from_str(&aamva_json).map_err(|e| {
                MdocInitError::GeneralConstructionError(format!("aamva JSON parse: {e}"))
            })?;
            let aamva_data = OrgIso1801351Aamva::from_json(&json_value)
                .map_err(|e| {
                    MdocInitError::GeneralConstructionError(format!("AAMVA namespace parse: {e}"))
                })?
                .to_ns_map();
            namespaces.insert("org.iso.18013.5.1.aamva".to_string(), aamva_data);
        }

        let doc_type = "org.iso.18013.5.1.mDL".to_string();
        let status_list = parse_status_json(status_list)?;
        let builder = prepare_builder(
            pub_key,
            namespaces,
            doc_type,
            status_list,
            default_validity_info(),
        )
        .map_err(|e| MdocInitError::GeneralConstructionError(format!("prepare_builder: {e}")))?;

        let algorithm = parse_signature_algorithm(&signature_algorithm)?;
        let prepared = builder
            .prepare(algorithm)
            .map_err(|e| MdocInitError::GeneralConstructionError(format!("prepare: {e}")))?;

        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(Some(prepared)),
        }))
    }

    /// Prepare an mDoc for external signing from CBOR-encoded element values.
    ///
    /// [`PreparedMdoc::new()`] converts JSON values, which cannot express byte strings or
    /// tagged values. This constructor takes each element value as CBOR bytes instead, so
    /// `full-date` (tag 1004), `tdate` (tag 0), byte strings and nested maps keep their CBOR
    /// types. Values are decoded and re-encoded, so the mdoc holds the same CBOR value but
    /// not necessarily the same bytes: an indefinite-length string, for example, becomes a
    /// definite-length one. Any doctype and any number of namespaces are accepted; the
    /// caller encodes and validates the values.
    ///
    /// * `namespaces` — namespace → (element identifier → one CBOR data item). Maps may not
    ///   repeat a key, at any depth.
    /// * `holder_jwk` — P-256 JWK of the holder's device key.
    /// * `signature_algorithm` — one of `"ES256"`, `"ES384"`, `"ES512"`.
    /// * `valid_until`, `valid_from`, `expected_update` — RFC 3339 date-times for the MSO
    ///   `validityInfo`, which records the time of this call as the signing time.
    ///   `valid_from` defaults to the signing time. A `valid_from` up to 60 seconds before
    ///   the signing time, such as a "now" taken by the caller just before this call, is
    ///   raised to the signing time; anything earlier is rejected. `valid_until` must be
    ///   later than `valid_from`. All times are truncated to whole seconds.
    /// * `status_list` — optional JSON status claim stored as the MSO `status`, e.g.
    ///   `{"status_list": {"idx": 1, "uri": "https://example.com/statuslists/1"}}`.
    #[uniffi::constructor(default(status_list = None, valid_from = None, expected_update = None))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_cbor(
        doc_type: String,
        namespaces: HashMap<String, HashMap<String, Vec<u8>>>,
        holder_jwk: String,
        signature_algorithm: String,
        valid_until: String,
        status_list: Option<String>,
        valid_from: Option<String>,
        expected_update: Option<String>,
    ) -> Result<Arc<Self>, MdocInitError> {
        let pub_key: PublicKey =
            PublicKey::from_jwk_str(&holder_jwk).map_err(|_e| MdocInitError::InvalidJwk)?;

        let namespaces = decode_cbor_namespaces(namespaces)?;
        let status_list = parse_status_json(status_list)?;
        let validity_info = validity_info(valid_from, valid_until, expected_update)?;
        let algorithm = parse_signature_algorithm(&signature_algorithm)?;

        let builder = prepare_builder(pub_key, namespaces, doc_type, status_list, validity_info)
            .map_err(|e| {
                MdocInitError::GeneralConstructionError(format!("prepare_builder: {e}"))
            })?;
        let prepared = builder
            .prepare(algorithm)
            .map_err(|e| MdocInitError::GeneralConstructionError(format!("prepare: {e}")))?;

        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(Some(prepared)),
        }))
    }

    /// Returns the bytes that must be signed by the issuer's key.
    pub fn signature_payload(&self) -> Result<Vec<u8>, MdocInitError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MdocInitError::GeneralConstructionError("lock poisoned".into()))?;
        let prepared = guard.as_ref().ok_or_else(|| {
            MdocInitError::GeneralConstructionError(
                "PreparedMdoc already consumed by complete()".into(),
            )
        })?;
        Ok(prepared.signature_payload().to_vec())
    }

    /// Supply the signature and certificate chain PEM to finalize the mDoc.
    ///
    /// `certificate_chain_pem` should contain the signing (leaf) certificate
    /// first, followed by any intermediate certificates. `signature` should be
    /// the raw signature bytes produced by signing [`signature_payload()`] with
    /// the issuer's private key.
    ///
    /// This method consumes the inner prepared data; calling it twice will fail.
    pub fn complete(
        &self,
        certificate_chain_pem: String,
        signature: Vec<u8>,
    ) -> Result<Arc<Mdoc>, MdocInitError> {
        let prepared = self
            .inner
            .lock()
            .map_err(|_| MdocInitError::GeneralConstructionError("lock poisoned".into()))?
            .take()
            .ok_or_else(|| {
                MdocInitError::GeneralConstructionError(
                    "PreparedMdoc already consumed by complete()".into(),
                )
            })?;

        let x5chain = parse_x5chain_from_pem(&certificate_chain_pem)?;
        let issuance_mdoc = prepared.complete(x5chain, signature);
        let doc = issuance_mdoc_to_document(issuance_mdoc)?;

        Ok(Arc::new(Mdoc::new_from_parts(
            doc,
            KeyAlias(Uuid::new_v4().to_string()),
        )))
    }
}

/// Map a string algorithm name to a COSE algorithm identifier.
fn parse_signature_algorithm(alg: &str) -> Result<iana::Algorithm, MdocInitError> {
    match alg.to_uppercase().as_str() {
        "ES256" => Ok(iana::Algorithm::ES256),
        "ES384" => Ok(iana::Algorithm::ES384),
        "ES512" => Ok(iana::Algorithm::ES512),
        _ => Err(MdocInitError::GeneralConstructionError(format!(
            "unsupported signature algorithm: {alg}"
        ))),
    }
}

/// Parse a PEM-encoded certificate chain into an X5Chain.
///
/// The first certificate in the PEM is the signing (leaf) certificate.
/// Subsequent certificates are intermediates.
fn parse_x5chain_from_pem(pem_str: &str) -> Result<X5Chain, MdocInitError> {
    let parts: Vec<&str> = pem_str.split("-----BEGIN CERTIFICATE-----").collect();
    let mut certs = Vec::new();

    for part in parts.iter().skip(1) {
        if part.trim().is_empty() {
            continue;
        }
        let full_pem = format!("-----BEGIN CERTIFICATE-----\n{}", part.trim_start());
        let cert = Certificate::from_pem(&full_pem).map_err(|e| {
            MdocInitError::GeneralConstructionError(format!("certificate PEM parse: {e}"))
        })?;
        certs.push(cert);
    }

    if certs.is_empty() {
        return Err(MdocInitError::GeneralConstructionError(
            "no certificates found in PEM data".into(),
        ));
    }

    let mut builder = X5Chain::builder()
        .with_certificate(certs.remove(0))
        .map_err(|e| {
            MdocInitError::GeneralConstructionError(format!("x5chain certificate: {e}"))
        })?;

    for cert in certs {
        builder = builder.with_certificate(cert).map_err(|e| {
            MdocInitError::GeneralConstructionError(format!("x5chain intermediate: {e}"))
        })?;
    }

    builder
        .build()
        .map_err(|e| MdocInitError::GeneralConstructionError(format!("x5chain build: {e}")))
}

/// Convert an upstream `isomdl::issuance::mdoc::Mdoc` into our `Document` wrapper.
fn issuance_mdoc_to_document(
    mdoc: isomdl::issuance::mdoc::Mdoc,
) -> Result<Document, MdocInitError> {
    let namespaces = NonEmptyMap::maybe_new(
        mdoc.namespaces
            .into_inner()
            .into_iter()
            .map(|(namespace, elements)| {
                let inner_map = NonEmptyMap::maybe_new(
                    elements
                        .into_inner()
                        .into_iter()
                        .map(|element| (element.as_ref().element_identifier.clone(), element))
                        .collect(),
                )
                .ok_or(MdocInitError::GeneralConstructionError(
                    "empty namespace elements".into(),
                ))?;
                Ok((namespace, inner_map))
            })
            .collect::<Result<_, MdocInitError>>()?,
    )
    .ok_or(MdocInitError::GeneralConstructionError(
        "empty namespaces".into(),
    ))?;

    Ok(Document {
        id: Default::default(),
        issuer_auth: mdoc.issuer_auth,
        mso: mdoc.mso,
        namespaces,
    })
}

fn prepare_builder(
    holder_key: PublicKey,
    namespaces: BTreeMap<String, BTreeMap<String, ciborium::Value>>,
    doc_type: String,
    status_list: Option<ciborium::Value>,
    validity_info: ValidityInfo,
) -> Result<Builder> {
    let digest_alg = DigestAlgorithm::SHA256;

    let ec = holder_key.to_encoded_point(false);
    let x = ec.x().context("EC missing X coordinate")?.to_vec();
    let y = EC2Y::Value(ec.y().context("EC missing X coordinate")?.to_vec());
    let device_key = CoseKey::EC2 {
        crv: EC2Curve::P256,
        x,
        y,
    };
    let device_key_info = DeviceKeyInfo {
        device_key,
        key_authorizations: None,
        key_info: None,
    };

    let mut builder = isomdl::issuance::Mdoc::builder()
        .doc_type(doc_type)
        .namespaces(namespaces)
        .validity_info(validity_info)
        .digest_algorithm(digest_alg)
        .device_key_info(device_key_info);

    if let Some(status_list) = status_list {
        builder = builder.status(status_list);
    }

    Ok(builder)
}

/// MSO validity used by the constructors that take no validity: thirty days from signing.
const DEFAULT_VALIDITY: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// `time` truncated to whole seconds, the precision of a `tdate` in the MSO.
fn whole_seconds(time: OffsetDateTime) -> OffsetDateTime {
    time.replace_nanosecond(0).unwrap_or(time)
}

/// Validity for the constructors that take none: signed and valid from now, valid for
/// [`DEFAULT_VALIDITY`], with no expected update.
fn default_validity_info() -> ValidityInfo {
    let signed = whole_seconds(OffsetDateTime::now_utc());
    ValidityInfo {
        signed,
        valid_from: signed,
        valid_until: signed + DEFAULT_VALIDITY,
        expected_update: None,
    }
}

/// Build the MSO validity from caller-supplied RFC 3339 date-times, for an mdoc signed now.
///
/// See [`validity_info_at`] for the rules.
fn validity_info(
    valid_from: Option<String>,
    valid_until: String,
    expected_update: Option<String>,
) -> Result<ValidityInfo, MdocInitError> {
    validity_info_at(
        OffsetDateTime::now_utc(),
        valid_from.as_deref(),
        &valid_until,
        expected_update.as_deref(),
    )
}

/// How far before the signing time a caller's `valid_from` may be and still be accepted.
/// It absorbs the gap between the caller reading the clock and the signing time being set.
const VALID_FROM_TOLERANCE: Duration = Duration::from_secs(60);

/// Build the MSO validity for an mdoc signed at `signed`.
///
/// Every time is truncated to whole seconds, as the MSO encodes it, before it is checked.
/// `valid_from` defaults to `signed`. A `valid_from` up to [`VALID_FROM_TOLERANCE`] before
/// `signed` is raised to `signed`, as the MSO requires; anything earlier is rejected.
/// `valid_until` must be later than `valid_from`. `expected_update` is not checked against
/// the others.
fn validity_info_at(
    signed: OffsetDateTime,
    valid_from: Option<&str>,
    valid_until: &str,
    expected_update: Option<&str>,
) -> Result<ValidityInfo, MdocInitError> {
    let signed = whole_seconds(signed);
    let valid_from = valid_from
        .map(|v| parse_rfc3339("valid_from", v))
        .transpose()?
        .unwrap_or(signed);
    let valid_until = parse_rfc3339("valid_until", valid_until)?;
    let expected_update = expected_update
        .map(|v| parse_rfc3339("expected_update", v))
        .transpose()?;

    if valid_from < signed - VALID_FROM_TOLERANCE {
        return Err(validity_error(&format!(
            "valid_from is more than {} seconds before the signing time",
            VALID_FROM_TOLERANCE.as_secs()
        )));
    }
    let valid_from = valid_from.max(signed);
    if valid_until <= valid_from {
        return Err(validity_error("valid_until is not later than valid_from"));
    }

    Ok(ValidityInfo {
        signed,
        valid_from,
        valid_until,
        expected_update,
    })
}

/// Parse an RFC 3339 date-time into UTC, truncated to whole seconds.
fn parse_rfc3339(field: &str, value: &str) -> Result<OffsetDateTime, MdocInitError> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|e| validity_error(&format!("{field} is not an RFC 3339 date-time: {e}")))?;
    OffsetDateTime::from_unix_timestamp(parsed.timestamp())
        .map_err(|e| validity_error(&format!("{field} is out of range: {e}")))
}

fn validity_error(message: &str) -> MdocInitError {
    MdocInitError::GeneralConstructionError(format!("validity: {message}"))
}

/// Parse a caller-supplied JSON status claim (e.g.
/// `{"status_list": {"idx": 1, "uri": "https://..."}}`) into the CBOR value
/// stored on the MSO.
fn parse_status_json(status_list: Option<String>) -> Result<Option<Value>, MdocInitError> {
    status_list
        .map(|s| {
            let json_val: serde_json::Value = serde_json::from_str(&s).map_err(|e| {
                MdocInitError::GeneralConstructionError(format!("status JSON parse: {e}"))
            })?;
            Ok(json_to_cbor(json_val))
        })
        .transpose()
}

/// Convert a [`serde_json::Value`] to an equivalent [`ciborium::Value`].
///
/// Used to translate JSON-encoded element values (supplied by callers) into
/// CBOR values that the isomdl namespace builder expects.
fn json_to_cbor(json: serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Float(0.0)
            }
        }
        serde_json::Value::String(s) => Value::Text(s),
        serde_json::Value::Array(arr) => Value::Array(arr.into_iter().map(json_to_cbor).collect()),
        serde_json::Value::Object(obj) => Value::Map(
            obj.into_iter()
                .map(|(k, v)| (Value::Text(k), json_to_cbor(v)))
                .collect(),
        ),
    }
}

/// Convert a caller-supplied namespace map (element identifier → JSON string)
/// into the BTreeMap<String, BTreeMap<String, ciborium::Value>> form that
/// [`prepare_builder`] requires.
///
/// Accepting JSON strings instead of raw CBOR bytes removes the need for
/// callers to depend on a CBOR library (e.g. `cbor2` in Python) just to
/// encode individual element values.
fn convert_namespaces_json(
    input: HashMap<String, HashMap<String, String>>,
) -> Result<BTreeMap<String, BTreeMap<String, Value>>, MdocInitError> {
    let mut outer = BTreeMap::new();

    for (namespace, inner_map) in input {
        let mut inner_btree = BTreeMap::new();
        for (key, json_str) in inner_map {
            let json_val: serde_json::Value = serde_json::from_str(&json_str).map_err(|_| {
                MdocInitError::DocumentCborDecoding(format!(
                    "Invalid JSON for element '{key}': {json_str:?}"
                ))
            })?;
            inner_btree.insert(key, json_to_cbor(json_val));
        }
        outer.insert(namespace, inner_btree);
    }

    Ok(outer)
}

/// Convert a namespace map of raw CBOR-encoded bytes into the
/// BTreeMap<String, BTreeMap<String, ciborium::Value>> form used internally.
///
/// Used by the OID4VP holder path where namespace values arrive as
/// pre-encoded CBOR bytes from the mDL presentation.
pub fn convert_namespaces(
    input: HashMap<String, HashMap<String, Vec<u8>>>,
) -> Result<BTreeMap<String, BTreeMap<String, Value>>, MdocInitError> {
    let mut outer = BTreeMap::new();

    for (namespace, inner_map) in input {
        let mut inner_btree = BTreeMap::new();
        for (key, vec_bytes) in inner_map {
            let mut cursor = Cursor::new(vec_bytes);
            let value: Value = ciborium::from_reader(&mut cursor).map_err(|_e| {
                MdocInitError::DocumentCborDecoding("Error decoding CBOR value".to_owned())
            })?;
            inner_btree.insert(key, value);
        }
        outer.insert(namespace, inner_btree);
    }

    Ok(outer)
}

/// Decode the CBOR-encoded element values given to [`PreparedMdoc::new_from_cbor`].
///
/// Stricter than [`convert_namespaces`]: there must be at least one namespace, every
/// namespace must have at least one element, every value must be exactly one CBOR data
/// item with no trailing bytes, and no map in a value may repeat a key. Errors name the
/// namespace and element, never the value.
fn decode_cbor_namespaces(
    input: HashMap<String, HashMap<String, Vec<u8>>>,
) -> Result<BTreeMap<String, BTreeMap<String, Value>>, MdocInitError> {
    if input.is_empty() {
        return Err(MdocInitError::GeneralConstructionError(
            "no namespaces given".into(),
        ));
    }

    let mut namespaces = BTreeMap::new();
    for (namespace, elements) in input {
        if elements.is_empty() {
            return Err(MdocInitError::GeneralConstructionError(format!(
                "namespace '{namespace}' has no elements"
            )));
        }
        let mut decoded = BTreeMap::new();
        for (element, bytes) in elements {
            let invalid = || {
                MdocInitError::GeneralConstructionError(format!(
                    "element '{element}' in namespace '{namespace}' is not a single CBOR data item"
                ))
            };
            let mut cursor = Cursor::new(bytes.as_slice());
            let value: Value = ciborium::from_reader(&mut cursor).map_err(|_| invalid())?;
            if cursor.position() != bytes.len() as u64 {
                return Err(invalid());
            }
            if has_duplicate_map_key(&value) {
                return Err(MdocInitError::GeneralConstructionError(format!(
                    "element '{element}' in namespace '{namespace}' has a map with a duplicate key"
                )));
            }
            decoded.insert(element, value);
        }
        namespaces.insert(namespace, decoded);
    }

    Ok(namespaces)
}

/// Whether `value` holds, at any depth, a map that repeats a key. RFC 8949 does not allow
/// duplicate keys, and decoders disagree on which entry wins, so a verifier could read a
/// different value from the one the issuer meant to sign.
///
/// Keys are compared by their encoding. Encoding a value that was just decoded cannot
/// fail, but if it does the map is treated as invalid.
fn has_duplicate_map_key(value: &Value) -> bool {
    match value {
        Value::Map(entries) => {
            let mut keys = HashSet::new();
            entries.iter().any(|(key, item)| {
                let mut encoded = Vec::new();
                ciborium::into_writer(key, &mut encoded).is_err()
                    || !keys.insert(encoded)
                    || has_duplicate_map_key(key)
                    || has_duplicate_map_key(item)
            })
        }
        Value::Array(items) => items.iter().any(has_duplicate_map_key),
        Value::Tag(_, inner) => has_duplicate_map_key(inner),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::{
        ecdsa::SigningKey,
        pkcs8::{EncodePrivateKey, LineEnding},
    };
    use std::time::Duration;
    use x509_cert::{
        builder::{Builder, CertificateBuilder, Profile},
        der::EncodePem,
        name::Name,
        serial_number::SerialNumber,
        spki::SubjectPublicKeyInfoOwned,
        time::Validity,
    };

    #[test]
    fn test_create_and_sign_mdl() {
        // 1. Generate Issuer Key
        let issuer_key = SigningKey::random(&mut OsRng);
        let issuer_key_pem = issuer_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();

        // 2. Generate Issuer Certificate (Self-signed for simplicity)
        let subject_name: Name = "CN=Test Issuer".parse().unwrap();
        let serial_number = SerialNumber::from(1u64);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();

        // Use clone() to ensure we have the value, not a reference, as expected by from_key
        let spki = SubjectPublicKeyInfoOwned::from_key(issuer_key.verifying_key().clone()).unwrap();

        let builder = CertificateBuilder::new(
            Profile::Root,
            serial_number,
            validity,
            subject_name,
            spki,
            &issuer_key,
        )
        .unwrap();

        let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();
        let cert_pem = cert.to_pem(LineEnding::LF).unwrap();

        // 3. Generate Holder Key (JWK)
        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let holder_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        })
        .to_string();

        // 4. Sample Data
        let mdl_items = serde_json::json!({
            "family_name": "Doe",
            "given_name": "John",
            "birth_date": "1990-01-01",
            "issue_date": "2023-01-01",
            "expiry_date": "2028-01-01",
            "issuing_country": "US",
            "issuing_authority": "DMV",
            "document_number": "123456789",
            "portrait": "SGVsbG8gV29ybGQ=",
            "driving_privileges": [
                {
                    "vehicle_category_code": "B",
                    "issue_date": "2023-01-01",
                    "expiry_date": "2028-01-01"
                }
            ],
            "un_distinguishing_sign": "USA"
        })
        .to_string();

        // 5. Call function
        let result =
            Mdoc::create_and_sign_mdl(mdl_items, None, holder_jwk, cert_pem, issuer_key_pem, None);

        let mdoc = result.unwrap();

        // 6. Verify Output
        assert_eq!(mdoc.doctype(), "org.iso.18013.5.1.mDL");

        let details = mdoc.details();
        let mdl_namespace = Namespace("org.iso.18013.5.1".to_string());
        let elements = details
            .get(&mdl_namespace)
            .expect("mDL namespace not found");

        let family_name = elements
            .iter()
            .find(|e| e.identifier == "family_name")
            .expect("family_name not found");
        assert!(family_name.value.as_ref().unwrap().contains("Doe"));

        let given_name = elements
            .iter()
            .find(|e| e.identifier == "given_name")
            .expect("given_name not found");
        assert!(given_name.value.as_ref().unwrap().contains("John"));

        let doc_num = elements
            .iter()
            .find(|e| e.identifier == "document_number")
            .expect("document_number not found");
        assert!(doc_num.value.as_ref().unwrap().contains("123456789"));
    }

    #[test]
    fn test_verify_issuer_signature_valid() {
        // 1. Generate Issuer Key
        let issuer_key = SigningKey::random(&mut OsRng);
        let issuer_key_pem = issuer_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();

        // 2. Generate Issuer Certificate (Self-signed for simplicity)
        let subject_name: Name = "CN=Test Issuer".parse().unwrap();
        let serial_number = SerialNumber::from(1u64);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();

        let spki = SubjectPublicKeyInfoOwned::from_key(issuer_key.verifying_key().clone()).unwrap();

        let builder = CertificateBuilder::new(
            Profile::Root,
            serial_number,
            validity,
            subject_name,
            spki,
            &issuer_key,
        )
        .unwrap();

        let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();
        let cert_pem = cert.to_pem(LineEnding::LF).unwrap();

        // 3. Generate Holder Key (JWK)
        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let holder_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        })
        .to_string();

        // 4. Sample Data
        let mdl_items = serde_json::json!({
            "family_name": "Doe",
            "given_name": "John",
            "birth_date": "1990-01-01",
            "issue_date": "2023-01-01",
            "expiry_date": "2028-01-01",
            "issuing_country": "US",
            "issuing_authority": "DMV",
            "document_number": "123456789",
            "portrait": "SGVsbG8gV29ybGQ=",
            "driving_privileges": [
                {
                    "vehicle_category_code": "B",
                    "issue_date": "2023-01-01",
                    "expiry_date": "2028-01-01"
                }
            ],
            "un_distinguishing_sign": "USA"
        })
        .to_string();

        // 5. Create mdoc
        let mdoc = Mdoc::create_and_sign_mdl(
            mdl_items,
            None,
            holder_jwk,
            cert_pem.clone(),
            issuer_key_pem,
            None,
        )
        .expect("Failed to create mdoc");

        // 6. Verify issuer signature without trust anchors (just signature check)
        let result = mdoc.verify_issuer_signature(None, false);
        assert!(result.is_ok(), "Verification should succeed: {:?}", result);

        let verification = result.unwrap();
        assert!(verification.verified, "Signature should be valid");
        // Note: setup_certificate_chain creates an intermediate "Test DS" certificate
        // signed by the provided IACA cert, so the common name is from the DS cert, not IACA
        assert_eq!(
            verification.common_name,
            Some("Test DS".to_string()),
            "Common name should match DS certificate"
        );
        assert!(verification.error.is_none(), "No error expected");

        // Note: We skip the trust anchor test here because the test certificate doesn't meet
        // all mDL validation requirements (country, state, CRL distribution points, etc.).
        // The test_verify_issuer_signature_invalid_trust_anchor test covers the trust anchor
        // validation path. For a real mDL issuance, proper IACA certificates would be used.
    }

    #[test]
    fn test_verify_issuer_signature_invalid_trust_anchor() {
        // 1. Generate Issuer Key and Certificate
        let issuer_key = SigningKey::random(&mut OsRng);
        let issuer_key_pem = issuer_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();

        let subject_name: Name = "CN=Test Issuer".parse().unwrap();
        let serial_number = SerialNumber::from(1u64);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();

        let spki = SubjectPublicKeyInfoOwned::from_key(issuer_key.verifying_key().clone()).unwrap();

        let builder = CertificateBuilder::new(
            Profile::Root,
            serial_number,
            validity,
            subject_name,
            spki,
            &issuer_key,
        )
        .unwrap();

        let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();
        let cert_pem = cert.to_pem(LineEnding::LF).unwrap();

        // 2. Generate a DIFFERENT key for a different trust anchor
        let other_key = SigningKey::random(&mut OsRng);
        let other_name: Name = "CN=Other Issuer".parse().unwrap();
        let other_spki =
            SubjectPublicKeyInfoOwned::from_key(other_key.verifying_key().clone()).unwrap();

        let other_builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(2u64),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            other_name,
            other_spki,
            &other_key,
        )
        .unwrap();

        let other_cert = other_builder.build::<p256::ecdsa::DerSignature>().unwrap();
        let other_cert_pem = other_cert.to_pem(LineEnding::LF).unwrap();

        // 3. Generate Holder Key (JWK)
        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let holder_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        })
        .to_string();

        // 4. Sample Data
        let mdl_items = serde_json::json!({
            "family_name": "Doe",
            "given_name": "John",
            "birth_date": "1990-01-01",
            "issue_date": "2023-01-01",
            "expiry_date": "2028-01-01",
            "issuing_country": "US",
            "issuing_authority": "DMV",
            "document_number": "123456789",
            "portrait": "SGVsbG8gV29ybGQ=",
            "driving_privileges": [
                {
                    "vehicle_category_code": "B",
                    "issue_date": "2023-01-01",
                    "expiry_date": "2028-01-01"
                }
            ],
            "un_distinguishing_sign": "USA"
        })
        .to_string();

        // 5. Create mdoc with original issuer
        let mdoc =
            Mdoc::create_and_sign_mdl(mdl_items, None, holder_jwk, cert_pem, issuer_key_pem, None)
                .expect("Failed to create mdoc");

        // 6. Try to verify with WRONG trust anchor - should fail validation
        let result = mdoc.verify_issuer_signature(Some(vec![other_cert_pem]), false);

        // The verification should fail because the mdoc's issuer cert is not trusted
        assert!(
            result.is_err(),
            "Verification should fail with untrusted anchor"
        );

        match result {
            Err(super::MdocVerificationError::X5ChainValidationFailed(_)) => {
                // Expected - the x5chain validation should fail
            }
            Err(e) => {
                panic!("Unexpected error type: {:?}", e);
            }
            Ok(_) => {
                panic!("Should have failed verification");
            }
        }
    }

    #[test]
    fn test_create_and_sign() {
        // 1. Generate Issuer Key
        let issuer_key = SigningKey::random(&mut OsRng);
        let issuer_key_pem = issuer_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();

        // 2. Generate Issuer Certificate
        let subject_name: Name = "CN=Test Issuer".parse().unwrap();
        let serial_number = SerialNumber::from(1u64);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_key(issuer_key.verifying_key().clone()).unwrap();

        let builder = CertificateBuilder::new(
            Profile::Root,
            serial_number,
            validity,
            subject_name,
            spki,
            &issuer_key,
        )
        .unwrap();

        let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();
        let cert_pem = cert.to_pem(LineEnding::LF).unwrap();

        // 3. Generate Holder Key (JWK)
        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let holder_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        })
        .to_string();

        // 4. Sample Data (Generic Namespace) — element values are JSON strings
        let mut namespaces = HashMap::new();
        let mut custom_ns = HashMap::new();
        custom_ns.insert(
            "custom-element".to_string(),
            serde_json::to_string("custom-value").unwrap(),
        );
        namespaces.insert("com.example.custom".to_string(), custom_ns);

        // 5. Call function
        let result = Mdoc::create_and_sign(
            "com.example.doc".to_string(),
            namespaces,
            holder_jwk,
            cert_pem,
            issuer_key_pem,
            None,
        );

        assert!(result.is_ok());
        let mdoc = result.unwrap();
        assert_eq!(mdoc.doctype(), "com.example.doc");

        let details = mdoc.details();
        let ns = Namespace("com.example.custom".to_string());
        let elements = details.get(&ns).expect("Namespace not found");
        let element = elements
            .iter()
            .find(|e| e.identifier == "custom-element")
            .expect("Element not found");
        assert!(element.value.as_ref().unwrap().contains("custom-value"));
    }

    #[test]
    fn test_issuer_signed_b64_iso_keys() {
        // Setup: mirrors test_create_and_sign with a generic namespace
        let issuer_key = SigningKey::random(&mut OsRng);
        let issuer_key_pem = issuer_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let spki = SubjectPublicKeyInfoOwned::from_key(issuer_key.verifying_key().clone()).unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u64),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            "CN=Test Issuer".parse().unwrap(),
            spki,
            &issuer_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();
        let cert_pem = cert.to_pem(LineEnding::LF).unwrap();

        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let holder_jwk =
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}).to_string();

        let mut namespaces = HashMap::new();
        let mut ns_items = HashMap::new();
        // Element values are JSON strings — no CBOR library needed at call site
        ns_items.insert(
            "given_name".to_string(),
            serde_json::to_string("Alice").unwrap(),
        );
        namespaces.insert("org.example.test".to_string(), ns_items);

        let mdoc = Mdoc::create_and_sign(
            "org.example.test.doc".to_string(),
            namespaces,
            holder_jwk,
            cert_pem,
            issuer_key_pem,
            None,
        )
        .expect("create_and_sign failed");

        // Exercise: serialize as ISO 18013-5 §8.3 compliant IssuerSigned
        let b64 = mdoc.issuer_signed_b64().expect("issuer_signed_b64 failed");

        // Decode base64url and parse as CBOR
        let cbor_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&b64)
            .expect("base64url decode failed");
        let value: Value =
            ciborium::from_reader(std::io::Cursor::new(&cbor_bytes)).expect("CBOR parse failed");

        let Value::Map(top_pairs) = value else {
            panic!("Expected CBOR map at top level");
        };

        // Collect text keys for readable assertions
        let keys: Vec<String> = top_pairs
            .iter()
            .filter_map(|(k, _)| {
                if let Value::Text(s) = k {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect();

        // ISO 18013-5 §8.3 requires camelCase keys in IssuerSigned
        assert!(
            keys.contains(&"issuerAuth".to_string()),
            "Expected 'issuerAuth' (ISO §8.3), got keys: {keys:?}"
        );
        assert!(
            keys.contains(&"nameSpaces".to_string()),
            "Expected 'nameSpaces' (ISO §8.3), got keys: {keys:?}"
        );
        assert!(
            !keys.contains(&"issuer_auth".to_string()),
            "Prohibited snake_case 'issuer_auth' present in CBOR output: {keys:?}"
        );
        assert!(
            !keys.contains(&"namespaces".to_string()),
            "Prohibited snake_case 'namespaces' present in CBOR output: {keys:?}"
        );

        // ISO 18013-5 §8.3: nameSpaces values must be CBOR arrays (NonEmptyVec<IssuerSignedItemBytes>)
        let ns_val = top_pairs
            .iter()
            .find(|(k, _)| k == &Value::Text("nameSpaces".to_string()))
            .map(|(_, v)| v)
            .expect("nameSpaces key unexpectedly missing");
        let Value::Map(ns_map) = ns_val else {
            panic!("Expected nameSpaces to be a CBOR map of namespace -> [items]");
        };
        assert!(!ns_map.is_empty(), "nameSpaces must not be empty");
        for (_, items_val) in ns_map {
            assert!(
                matches!(items_val, Value::Array(_)),
                "Each namespace value must be a CBOR array (ISO §8.3), got: {items_val:?}"
            );
        }

        // Bonus: round-trip — the b64 must be parseable by Mdoc::new_from_base64url_encoded_issuer_signed
        let key_alias = KeyAlias("test-alias".to_string());
        let parsed = Mdoc::new_from_base64url_encoded_issuer_signed(b64.clone(), key_alias);
        assert!(
            parsed.is_ok(),
            "issuer_signed_b64 output must be parseable by new_from_base64url_encoded_issuer_signed: {:?}",
            parsed.err()
        );
    }

    #[test]
    fn test_create_and_sign_mdl_with_status_claim() {
        let issuer_key = SigningKey::random(&mut OsRng);
        let issuer_key_pem = issuer_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let spki = SubjectPublicKeyInfoOwned::from_key(issuer_key.verifying_key().clone()).unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u64),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            "CN=Test Issuer".parse().unwrap(),
            spki,
            &issuer_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();
        let cert_pem = cert.to_pem(LineEnding::LF).unwrap();

        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let holder_jwk =
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}).to_string();

        let mdl_items = serde_json::json!({
            "family_name": "Doe",
            "given_name": "John",
            "birth_date": "1990-01-01",
            "issue_date": "2023-01-01",
            "expiry_date": "2028-01-01",
            "issuing_country": "US",
            "issuing_authority": "DMV",
            "document_number": "123456789",
            "portrait": "SGVsbG8gV29ybGQ=",
            "driving_privileges": [
                {
                    "vehicle_category_code": "B",
                    "issue_date": "2023-01-01",
                    "expiry_date": "2028-01-01"
                }
            ],
            "un_distinguishing_sign": "USA"
        })
        .to_string();

        let status_json =
            r#"{"status_list":{"idx":42,"uri":"https://example.com/statuslists/1"}}"#.to_string();

        let mdoc = Mdoc::create_and_sign_mdl(
            mdl_items.clone(),
            None,
            holder_jwk.clone(),
            cert_pem.clone(),
            issuer_key_pem.clone(),
            Some(status_json.clone()),
        )
        .expect("create_and_sign_mdl with status failed");

        let status_list: serde_json::Value =
            serde_json::from_str(&mdoc.status_list().expect("status claim missing")).unwrap();
        let expected: serde_json::Value = serde_json::from_str(&status_json).unwrap();
        assert_eq!(status_list, expected);

        // Omitting `status_list` must leave it unset (backward compatible).
        let mdoc_without_status =
            Mdoc::create_and_sign_mdl(mdl_items, None, holder_jwk, cert_pem, issuer_key_pem, None)
                .expect("create_and_sign_mdl without status failed");
        assert_eq!(mdoc_without_status.status_list(), None);
    }

    #[test]
    fn test_status_json_parse_error_is_reported() {
        // Invalid JSON syntax must surface as a clean error, not panic or be
        // silently dropped.
        let err = parse_status_json(Some("{not valid json".to_string()))
            .expect_err("invalid JSON should be rejected");
        assert!(
            matches!(err, MdocInitError::GeneralConstructionError(_)),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn test_status_json_non_object_is_accepted_opaquely() {
        // Mirrors isomdl's own `malformed_status_value_is_not_rejected`: the
        // library treats the status claim as opaque CBOR and doesn't validate
        // its shape, so syntactically-valid JSON that isn't the expected
        // `{"status_list": {...}}` shape is still accepted rather than
        // rejected.
        let value = parse_status_json(Some("true".to_string()))
            .expect("syntactically valid JSON should parse")
            .expect("Some status_list should produce Some CBOR value");
        assert_eq!(value, Value::Bool(true));
    }

    #[test]
    fn test_prepare_and_complete_with_status_claim() {
        let ds_key = SigningKey::random(&mut OsRng);
        let spki = SubjectPublicKeyInfoOwned::from_key(ds_key.verifying_key().clone()).unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u64),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            "CN=Test Issuer".parse().unwrap(),
            spki,
            &ds_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();
        let cert_pem = cert.to_pem(LineEnding::LF).unwrap();

        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let holder_jwk =
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}).to_string();

        let mut namespaces = HashMap::new();
        let mut ns_items = HashMap::new();
        ns_items.insert(
            "given_name".to_string(),
            serde_json::to_string("Alice").unwrap(),
        );
        namespaces.insert("com.example.test".to_string(), ns_items);

        let status_json =
            r#"{"status_list":{"idx":7,"uri":"https://example.com/statuslists/1"}}"#.to_string();

        let prepared = PreparedMdoc::new(
            "com.example.test.doc".to_string(),
            namespaces,
            holder_jwk,
            "ES256".to_string(),
            Some(status_json.clone()),
        )
        .expect("prepare with status failed");

        let payload = prepared.signature_payload().expect("payload failed");
        use p256::ecdsa::{Signature, signature::Signer};
        let signature: Signature = ds_key.sign(&payload);

        let mdoc = prepared
            .complete(cert_pem, signature.to_vec())
            .expect("complete failed");

        let status_list: serde_json::Value =
            serde_json::from_str(&mdoc.status_list().expect("status claim missing")).unwrap();
        let expected: serde_json::Value = serde_json::from_str(&status_json).unwrap();
        assert_eq!(status_list, expected);
    }

    #[test]
    fn test_verify_issuer_signature_chaining() {
        use x509_cert::ext::pkix::{
            CrlDistributionPoints, IssuerAltName,
            crl::dp::DistributionPoint,
            name::{DistributionPointName, GeneralName},
        };

        // 1. Generate Root CA Key and Certificate
        let root_key = SigningKey::random(&mut OsRng);
        let root_subject: Name = "CN=Root CA,C=US,ST=NY,O=SpruceID".parse().unwrap();
        let root_spki =
            SubjectPublicKeyInfoOwned::from_key(root_key.verifying_key().clone()).unwrap();

        let root_builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u64),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            root_subject.clone(),
            root_spki,
            &root_key,
        )
        .unwrap();

        let root_cert = root_builder.build::<p256::ecdsa::DerSignature>().unwrap();
        let root_cert_pem = root_cert.to_pem(LineEnding::LF).unwrap();

        // 2. Generate Intermediate CA Key and Certificate (Signed by Root)
        let intermediate_key = SigningKey::random(&mut OsRng);
        let intermediate_subject: Name =
            "CN=Intermediate CA,C=US,ST=NY,O=SpruceID".parse().unwrap();
        let intermediate_spki =
            SubjectPublicKeyInfoOwned::from_key(intermediate_key.verifying_key().clone()).unwrap();

        let mut intermediate_builder = CertificateBuilder::new(
            Profile::SubCA {
                issuer: root_subject.clone(),
                path_len_constraint: Some(0),
            },
            SerialNumber::from(2u64),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            intermediate_subject,
            intermediate_spki,
            &root_key, // Signed by Root Key
        )
        .unwrap();

        // Add required extensions for mDL IACA profile
        intermediate_builder
            .add_extension(&CrlDistributionPoints(vec![DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::UniformResourceIdentifier(
                        "https://example.com/crl".to_string().try_into().unwrap(),
                    ),
                ])),
                reasons: None,
                crl_issuer: None,
            }]))
            .unwrap();

        intermediate_builder
            .add_extension(&IssuerAltName(vec![GeneralName::Rfc822Name(
                "ca@example.com".to_string().try_into().unwrap(),
            )]))
            .unwrap();

        let intermediate_cert = intermediate_builder
            .build::<p256::ecdsa::DerSignature>()
            .unwrap();
        let intermediate_cert_pem = intermediate_cert.to_pem(LineEnding::LF).unwrap();
        let intermediate_key_pem = intermediate_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();

        // 3. Generate Holder Key (JWK)
        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let holder_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        })
        .to_string();

        // 4. Sample Data
        let mdl_items = serde_json::json!({
            "family_name": "Doe",
            "given_name": "Jane",
            "birth_date": "1992-01-01",
            "issue_date": "2023-01-01",
            "expiry_date": "2028-01-01",
            "issuing_country": "US",
            "issuing_authority": "DMV",
            "document_number": "987654321",
            "portrait": "SGVsbG8gV29ybGQ=",
            "driving_privileges": [],
            "un_distinguishing_sign": "USA"
        })
        .to_string();

        // 5. Create mdoc signed by Intermediate CA
        // This will create a chain: [Ephemeral DS, Intermediate CA]
        let mdoc = Mdoc::create_and_sign_mdl(
            mdl_items,
            None,
            holder_jwk,
            intermediate_cert_pem.clone(),
            intermediate_key_pem,
            None,
        )
        .expect("Failed to create mdoc");

        // 6. Verify with Root CA as trust anchor

        // Case A: Chaining Disabled (Default) - Should Fail
        // The mDL is signed by Ephemeral DS, which is signed by Intermediate.
        // We only trust Root. Intermediate is not in trust anchors.
        let result_no_chain =
            mdoc.verify_issuer_signature(Some(vec![root_cert_pem.clone()]), false);
        assert!(
            result_no_chain.is_err(),
            "Verification should fail when chaining is disabled and intermediate is missing from anchors"
        );

        // Case B: Chaining Enabled - Should Succeed
        // The verifier should find Intermediate in the x5chain, verify it against Root, and then verify Ephemeral DS against Intermediate.
        let result_chain = mdoc.verify_issuer_signature(Some(vec![root_cert_pem]), true);
        assert!(
            result_chain.is_ok(),
            "Verification should succeed when chaining is enabled: {:?}",
            result_chain.err()
        );

        let verification = result_chain.unwrap();
        assert!(verification.verified);
        // Common name should be the Ephemeral DS created by setup_certificate_chain
        assert_eq!(verification.common_name, Some("Test DS".to_string()));
    }

    #[test]
    fn test_prepare_and_complete() {
        // 1. Generate Issuer/DS Key
        let ds_key = SigningKey::random(&mut OsRng);
        let ds_key_pem = ds_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();

        // 2. Generate self-signed DS Certificate
        let subject_name: Name = "CN=Test Issuer".parse().unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_key(ds_key.verifying_key().clone()).unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u64),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            subject_name,
            spki,
            &ds_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();
        let cert_pem = cert.to_pem(LineEnding::LF).unwrap();

        // 3. Generate Holder Key (JWK)
        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let holder_jwk =
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}).to_string();

        // 4. Sample Data
        let mut namespaces = HashMap::new();
        let mut ns_items = HashMap::new();
        ns_items.insert(
            "given_name".to_string(),
            serde_json::to_string("Alice").unwrap(),
        );
        ns_items.insert(
            "family_name".to_string(),
            serde_json::to_string("Wonderland").unwrap(),
        );
        namespaces.insert("com.example.test".to_string(), ns_items);

        // 5. Prepare
        let prepared = PreparedMdoc::new(
            "com.example.test.doc".to_string(),
            namespaces,
            holder_jwk,
            "ES256".to_string(),
            None,
        )
        .expect("prepare failed");

        // 6. Get signature payload
        let payload = prepared.signature_payload().expect("payload failed");
        assert!(!payload.is_empty(), "signature payload should be non-empty");

        // 7. Sign externally with the DS key
        use p256::ecdsa::{Signature, signature::Signer};
        let signature: Signature = ds_key.sign(&payload);

        // 8. Complete
        let mdoc = prepared
            .complete(cert_pem, signature.to_vec())
            .expect("complete failed");

        // 9. Verify
        assert_eq!(mdoc.doctype(), "com.example.test.doc");
        let details = mdoc.details();
        let ns = Namespace("com.example.test".to_string());
        let elements = details.get(&ns).expect("Namespace not found");
        let given = elements
            .iter()
            .find(|e| e.identifier == "given_name")
            .expect("given_name not found");
        assert!(given.value.as_ref().unwrap().contains("Alice"));

        // 10. Verify calling complete again fails (consumed)
        let result = prepared.complete("".to_string(), vec![]);
        assert!(result.is_err(), "second complete should fail");
    }

    #[test]
    fn test_prepare_and_complete_matches_create_and_sign() {
        // Verify that the prepare/complete path produces a structurally valid
        // mDoc that can pass issuer signature verification, just like
        // create_and_sign does.
        let ds_key = SigningKey::random(&mut OsRng);
        let spki = SubjectPublicKeyInfoOwned::from_key(ds_key.verifying_key().clone()).unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u64),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            "CN=Test Issuer".parse().unwrap(),
            spki,
            &ds_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();
        let cert_pem = cert.to_pem(LineEnding::LF).unwrap();

        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let holder_jwk =
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}).to_string();

        let mut namespaces = HashMap::new();
        let mut ns_items = HashMap::new();
        ns_items.insert(
            "element_a".to_string(),
            serde_json::to_string("value_a").unwrap(),
        );
        namespaces.insert("com.example.verify".to_string(), ns_items);

        let prepared = PreparedMdoc::new(
            "com.example.verify.doc".to_string(),
            namespaces,
            holder_jwk,
            "ES256".to_string(),
            None,
        )
        .expect("prepare failed");

        let payload = prepared.signature_payload().expect("payload failed");
        use p256::ecdsa::{Signature, signature::Signer};
        let signature: Signature = ds_key.sign(&payload);

        let mdoc = prepared
            .complete(cert_pem.clone(), signature.to_vec())
            .expect("complete failed");

        // Verify the issuer signature passes (no trust anchors, just sig check)
        let result = mdoc.verify_issuer_signature(None, false);
        assert!(
            result.is_ok(),
            "issuer signature verification failed: {:?}",
            result
        );
        let verification = result.unwrap();
        assert!(verification.verified, "signature should be valid");

        // The cert was self-signed with CN=Test Issuer, used directly (no
        // intermediate DS cert generation), so the common name should match.
        assert_eq!(verification.common_name, Some("Test Issuer".to_string()),);
    }

    #[test]
    fn test_prepare_invalid_algorithm() {
        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let holder_jwk =
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}).to_string();

        let mut namespaces = HashMap::new();
        let mut ns_items = HashMap::new();
        ns_items.insert("k".to_string(), serde_json::to_string("v").unwrap());
        namespaces.insert("ns".to_string(), ns_items);

        let result = PreparedMdoc::new(
            "doc".to_string(),
            namespaces,
            holder_jwk,
            "INVALID".to_string(),
            None,
        );
        assert!(result.is_err(), "should reject unknown algorithm");
    }

    /// A self-signed P-256 document signer: its key and certificate PEM.
    fn cbor_test_signer() -> (SigningKey, String) {
        let ds_key = SigningKey::random(&mut OsRng);
        let spki = SubjectPublicKeyInfoOwned::from_key(*ds_key.verifying_key()).unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u64),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            "CN=Test Issuer".parse().unwrap(),
            spki,
            &ds_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();
        (ds_key, cert.to_pem(LineEnding::LF).unwrap())
    }

    fn cbor_test_holder_jwk() -> String {
        let holder_key = SigningKey::random(&mut OsRng);
        let point = holder_key.verifying_key().to_encoded_point(false);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}).to_string()
    }

    fn to_cbor(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap();
        bytes
    }

    fn rfc3339(time: OffsetDateTime) -> String {
        chrono::DateTime::from_timestamp(time.unix_timestamp(), 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    /// Element values covering the CBOR types `new_from_cbor` must keep, across three
    /// namespaces: text, a nested map holding a tagged date (the ISO/IEC 23220-1
    /// `birth_date`), a byte string, `full-date` and `tdate` tags, a boolean and an integer.
    fn cbor_test_namespaces() -> BTreeMap<String, BTreeMap<String, Value>> {
        let text = |s: &str| Value::Text(s.to_string());
        let full_date = |s: &str| Value::Tag(1004, Box::new(text(s)));
        BTreeMap::from([
            (
                "org.iso.23220.1".to_string(),
                BTreeMap::from([
                    ("family_name".to_string(), text("Smith")),
                    (
                        "birth_date".to_string(),
                        Value::Map(vec![
                            (text("birth_date"), full_date("1990-04-01")),
                            (text("approximate_mask"), text("00000011")),
                        ]),
                    ),
                    (
                        "portrait".to_string(),
                        Value::Bytes(vec![0xFF, 0xD8, 0xFF, 0xE0]),
                    ),
                    ("issue_date".to_string(), full_date("2026-01-01")),
                    (
                        "portrait_capture_date".to_string(),
                        Value::Tag(0, Box::new(text("2025-12-01T10:00:00Z"))),
                    ),
                    ("age_over_18".to_string(), Value::Bool(true)),
                    ("age_in_years".to_string(), Value::Integer(35.into())),
                ]),
            ),
            (
                "org.iso.23220.photoid.1".to_string(),
                BTreeMap::from([("person_id".to_string(), text("1234567890"))]),
            ),
            (
                "ca.on.photoid.1".to_string(),
                BTreeMap::from([(
                    "health_card".to_string(),
                    Value::Map(vec![(text("number"), text("1234-567-890"))]),
                )]),
            ),
        ])
    }

    fn encode_namespaces(
        namespaces: &BTreeMap<String, BTreeMap<String, Value>>,
    ) -> HashMap<String, HashMap<String, Vec<u8>>> {
        namespaces
            .iter()
            .map(|(namespace, elements)| {
                let encoded = elements
                    .iter()
                    .map(|(element, value)| (element.clone(), to_cbor(value)))
                    .collect();
                (namespace.clone(), encoded)
            })
            .collect()
    }

    /// The element values of `mdoc`, namespace by namespace.
    fn mdoc_element_values(mdoc: &Mdoc) -> BTreeMap<String, BTreeMap<String, Value>> {
        mdoc.inner
            .namespaces
            .iter()
            .map(|(namespace, elements)| {
                let values = elements
                    .iter()
                    .map(|(element, item)| (element.clone(), item.as_ref().element_value.clone()))
                    .collect();
                (namespace.clone(), values)
            })
            .collect()
    }

    /// Prepare with `new_from_cbor`, sign with a test document signer, and complete.
    fn issue_from_cbor(
        namespaces: HashMap<String, HashMap<String, Vec<u8>>>,
        valid_until: String,
        status_list: Option<String>,
        valid_from: Option<String>,
        expected_update: Option<String>,
    ) -> Arc<Mdoc> {
        let (ds_key, cert_pem) = cbor_test_signer();
        let prepared = PreparedMdoc::new_from_cbor(
            "org.iso.23220.photoid.1".to_string(),
            namespaces,
            cbor_test_holder_jwk(),
            "ES256".to_string(),
            valid_until,
            status_list,
            valid_from,
            expected_update,
        )
        .expect("new_from_cbor failed");

        use p256::ecdsa::{Signature, signature::Signer};
        let signature: Signature = ds_key.sign(&prepared.signature_payload().unwrap());
        // COSE ES256 takes the raw 64-byte r || s, which is also what an ACA-Py wallet
        // returns for a P-256 key.
        let signature = signature.to_vec();
        assert_eq!(signature.len(), 64);

        let mdoc = prepared
            .complete(cert_pem, signature)
            .expect("complete failed");
        assert!(
            prepared.complete(String::new(), vec![]).is_err(),
            "second complete should fail"
        );
        mdoc
    }

    #[test]
    fn test_new_from_cbor_keeps_cbor_types_across_namespaces() {
        let expected = cbor_test_namespaces();
        let in_30_days = rfc3339(OffsetDateTime::now_utc() + DEFAULT_VALIDITY);
        let mdoc = issue_from_cbor(encode_namespaces(&expected), in_30_days, None, None, None);

        assert_eq!(mdoc.doctype(), "org.iso.23220.photoid.1");
        assert_eq!(mdoc_element_values(&mdoc), expected);

        // The values also survive the IssuerSigned encoding sent to wallets.
        let reparsed = Mdoc::new_from_base64url_encoded_issuer_signed(
            mdoc.issuer_signed_b64().unwrap(),
            KeyAlias("reparsed".to_string()),
        )
        .unwrap();
        assert_eq!(mdoc_element_values(&reparsed), expected);

        let result = mdoc.verify_issuer_signature(None, false).unwrap();
        assert!(result.verified, "issuer signature: {:?}", result.error);
    }

    #[test]
    fn test_new_from_cbor_sets_validity_and_status() {
        let now = whole_seconds(OffsetDateTime::now_utc());
        let valid_from = now + Duration::from_secs(60 * 60);
        let valid_until = now + Duration::from_secs(90 * 24 * 60 * 60);
        let expected_update = now + Duration::from_secs(7 * 24 * 60 * 60);
        let status_json = r#"{"status_list":{"idx":3,"uri":"https://example.com/statuslists/2"}}"#;

        let mdoc = issue_from_cbor(
            encode_namespaces(&cbor_test_namespaces()),
            rfc3339(valid_until),
            Some(status_json.to_string()),
            Some(rfc3339(valid_from)),
            Some(rfc3339(expected_update)),
        );

        // Read the MSO back from the encoded IssuerSigned, as a wallet would.
        let reparsed = Mdoc::new_from_base64url_encoded_issuer_signed(
            mdoc.issuer_signed_b64().unwrap(),
            KeyAlias("reparsed".to_string()),
        )
        .unwrap();
        let validity = &reparsed.inner.mso.validity_info;
        assert!(validity.signed >= now && validity.signed <= valid_from);
        assert_eq!(validity.valid_from, valid_from);
        assert_eq!(validity.valid_until, valid_until);
        assert_eq!(validity.expected_update, Some(expected_update));

        let status: serde_json::Value =
            serde_json::from_str(&reparsed.status_list().expect("status claim missing")).unwrap();
        let expected: serde_json::Value = serde_json::from_str(status_json).unwrap();
        assert_eq!(status, expected);

        let result = mdoc.verify_issuer_signature(None, false).unwrap();
        assert!(result.verified, "issuer signature: {:?}", result.error);
    }

    #[test]
    fn test_validity_rules() {
        // 2026-01-01T00:00:00Z
        let signed = OffsetDateTime::from_unix_timestamp(1_767_225_600).unwrap();

        let validity = validity_info_at(signed, None, "2026-01-31T00:00:00Z", None).unwrap();
        assert_eq!(validity.valid_from, signed);
        assert_eq!(validity.expected_update, None);

        // Offsets and fractional seconds are normalised to whole seconds in UTC.
        let validity = validity_info_at(
            signed + Duration::from_millis(400),
            Some("2026-01-01T05:00:00.750+05:00"),
            "2026-01-31T00:00:00Z",
            None,
        )
        .unwrap();
        assert_eq!(validity.signed, signed);
        assert_eq!(validity.valid_from, signed);

        // A valid_from up to 60 seconds before signing, such as the caller's "now" just
        // before a second boundary, is raised to the signing time.
        for valid_from in ["2025-12-31T23:59:00Z", "2025-12-31T23:59:59.999Z"] {
            let validity =
                validity_info_at(signed, Some(valid_from), "2026-01-31T00:00:00Z", None).unwrap();
            assert_eq!(validity.valid_from, signed, "{valid_from}");
        }

        let rejected = [
            (
                Some("2025-12-31T23:58:59Z"),
                "2026-01-31T00:00:00Z",
                None,
                "valid_from is more than 60 seconds before the signing time",
            ),
            (
                None,
                "2026-01-01T00:00:00Z",
                None,
                "valid_until is not later than valid_from",
            ),
            (
                Some("2026-02-01T00:00:00Z"),
                "2026-01-31T00:00:00Z",
                None,
                "valid_until is not later than valid_from",
            ),
            (None, "31/01/2026", None, "valid_until is not an RFC 3339"),
            (
                Some("2026-01-01"),
                "2026-01-31T00:00:00Z",
                None,
                "valid_from is not an RFC 3339",
            ),
            (
                None,
                "2026-01-31T00:00:00Z",
                Some("soon"),
                "expected_update is not an RFC 3339",
            ),
        ];
        for (valid_from, valid_until, expected_update, reason) in rejected {
            let err = validity_info_at(signed, valid_from, valid_until, expected_update)
                .expect_err(reason);
            assert!(
                err.to_string().contains(reason),
                "{err} should say {reason:?}"
            );
        }

        // The constructor applies the same rules.
        let result = PreparedMdoc::new_from_cbor(
            "doc".to_string(),
            encode_namespaces(&cbor_test_namespaces()),
            cbor_test_holder_jwk(),
            "ES256".to_string(),
            "2000-01-01T00:00:00Z".to_string(),
            None,
            None,
            None,
        );
        assert!(
            result.is_err(),
            "valid_until in the past should be rejected"
        );
    }

    #[test]
    fn test_new_from_cbor_rejects_bad_namespaces() {
        let in_30_days = rfc3339(OffsetDateTime::now_utc() + DEFAULT_VALIDITY);
        let prepare = |namespaces: HashMap<String, HashMap<String, Vec<u8>>>| {
            PreparedMdoc::new_from_cbor(
                "doc".to_string(),
                namespaces,
                cbor_test_holder_jwk(),
                "ES256".to_string(),
                in_30_days.clone(),
                None,
                None,
                None,
            )
            .map(|_| ())
            .unwrap_err()
            .to_string()
        };

        assert!(prepare(HashMap::new()).contains("no namespaces given"));
        assert!(
            prepare(HashMap::from([("ns".to_string(), HashMap::new())]))
                .contains("namespace 'ns' has no elements")
        );

        let not_one_item = "is not a single CBOR data item";
        let truncated = vec![0x62, b'Q']; // a two-byte text string with one byte present
        let trailing = [to_cbor(&Value::Text("ok".to_string())), vec![0x00]].concat();
        let duplicate_key = |key: Value| {
            let map = Value::Map(vec![
                (key.clone(), Value::Text("Q1".to_string())),
                (key, Value::Text("Q2".to_string())),
            ]);
            // Nested in a tag and an array, to check the search goes all the way down.
            to_cbor(&Value::Tag(
                65536,
                Box::new(Value::Array(vec![Value::Bool(true), map])),
            ))
        };
        let cases = [
            (truncated, not_one_item),
            (trailing, not_one_item),
            (vec![], not_one_item),
            (
                duplicate_key(Value::Text("Q".to_string())),
                "has a map with a duplicate key",
            ),
            (
                duplicate_key(Value::Integer(7.into())),
                "has a map with a duplicate key",
            ),
        ];
        for (bytes, reason) in cases {
            let element = HashMap::from([("el".to_string(), bytes)]);
            let message = prepare(HashMap::from([("ns".to_string(), element)]));
            assert!(
                message.contains(&format!("element 'el' in namespace 'ns' {reason}")),
                "{message}"
            );
            assert!(
                !message.contains('Q'),
                "error must not echo the value: {message}"
            );
        }
    }

    #[test]
    fn test_default_validity_is_thirty_days_from_signing() {
        let validity = default_validity_info();
        assert_eq!(validity.valid_from, validity.signed);
        assert_eq!(validity.valid_until, validity.signed + DEFAULT_VALIDITY);
        assert_eq!(validity.expected_update, None);
        assert_eq!(validity.signed, whole_seconds(validity.signed));
    }
}
