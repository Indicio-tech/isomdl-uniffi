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
    collections::{BTreeMap, HashMap},
    io::Cursor,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use base64::prelude::*;
use ciborium::{Value, from_reader};
use isomdl::{
    definitions::{
        CoseKey, DeviceKeyInfo, DigestAlgorithm, EC2Curve, EC2Y, IssuerSigned, Mso, ValidityInfo,
        helpers::{NonEmptyMap, Tag24},
        x509::X5Chain,
    },
    issuance::mdoc::Builder,
    presentation::{Stringify, device::Document},
};
use p256::{PublicKey, elliptic_curve::sec1::ToEncodedPoint};
use serde::Deserialize;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::util::setup_certificate_chain;

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
        namespaces: HashMap<String, HashMap<String, Vec<u8>>>,
        holder_jwk: String,
        iaca_cert_perm: String,
        iaca_key_perm: String,
    ) -> Result<Arc<Self>, MdocInitError> {
        let pub_key: PublicKey =
            PublicKey::from_jwk_str(&holder_jwk).map_err(|_e| MdocInitError::InvalidJwk)?;

        let namespaces = convert_namespaces(namespaces)?;
        let builder = prepare_builder(pub_key, namespaces, doc_type)
            .map_err(|_e| MdocInitError::GeneralConstructionError)?;

        let (certificate, signer) = setup_certificate_chain(iaca_cert_perm, iaca_key_perm)
            .map_err(|_e| MdocInitError::GeneralConstructionError)?;

        let x5chain = X5Chain::builder()
            .with_certificate(certificate)
            .map_err(|_e| MdocInitError::GeneralConstructionError)?
            .build()
            .map_err(|_e| MdocInitError::GeneralConstructionError)?;

        let mdoc = builder
            .issue::<p256::ecdsa::SigningKey, p256::ecdsa::Signature>(x5chain, signer)
            .map_err(|_e| MdocInitError::GeneralConstructionError)?;

        let namespaces = NonEmptyMap::maybe_new(
            mdoc.namespaces
                .into_inner()
                .into_iter()
                .map(|(namespace, elements)| {
                    (
                        namespace,
                        NonEmptyMap::maybe_new(
                            elements
                                .into_inner()
                                .into_iter()
                                .map(|element| {
                                    (element.as_ref().element_identifier.clone(), element)
                                })
                                .collect(),
                        )
                        .unwrap(),
                    )
                })
                .collect(),
        )
        .unwrap();

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
                    // Unwrap safety: safe to convert BTreeMap to NonEmptyMap since we're iterating over a NonEmptyVec.
                    .unwrap();
                (k, m)
            })
            .collect::<BTreeMap<_, _>>()
            .try_into()
            // Unwrap safety: safe to convert BTreeMap to NonEmptyMap since we're iterating over a NonEmptyMap.
            .unwrap();

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
    #[error("failed to construct mdoc")]
    GeneralConstructionError,
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum MdocEncodingError {
    #[error("failed to encode Document to CBOR")]
    DocumentCborEncoding,
    #[error("failed to serialize mdoc")]
    SerializationError,
}

fn prepare_builder(
    holder_key: PublicKey,
    namespaces: BTreeMap<String, BTreeMap<String, ciborium::Value>>,
    doc_type: String,
) -> Result<Builder> {
    let validity_info = ValidityInfo {
        signed: OffsetDateTime::now_utc(),
        valid_from: OffsetDateTime::now_utc(),
        // mDL valid for thirty days.
        valid_until: OffsetDateTime::now_utc() + Duration::from_secs(60 * 60 * 24 * 30),
        expected_update: None,
    };

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

    Ok(isomdl::issuance::Mdoc::builder()
        .doc_type(doc_type)
        .namespaces(namespaces)
        .validity_info(validity_info)
        .digest_algorithm(digest_alg)
        .device_key_info(device_key_info))
}

fn convert_namespaces(
    input: HashMap<String, HashMap<String, Vec<u8>>>,
) -> Result<BTreeMap<String, BTreeMap<String, Value>>, MdocInitError> {
    let mut outer = BTreeMap::new();

    for (namespace, inner_map) in input {
        let mut inner_btree = BTreeMap::new();
        for (key, vec_bytes) in inner_map {
            let mut cursor = Cursor::new(vec_bytes);
            let value: Value = from_reader(&mut cursor).map_err(|_e| {
                MdocInitError::DocumentCborDecoding("Error decoding CBOR value".to_owned())
            })?;
            inner_btree.insert(key, value);
        }
        outer.insert(namespace, inner_btree);
    }

    Ok(outer)
}
