use std::collections::HashMap;
use crate::mdl::mdoc::{Mdoc, MdocInitError};

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum IssuerError {
    #[error("Issuance failed: {0}")]
    IssuanceFailed(String),
}

impl From<MdocInitError> for IssuerError {
    fn from(err: MdocInitError) -> Self {
        IssuerError::IssuanceFailed(format!("{:?}", err))
    }
}

/// Ultra-simplified mDoc issuer - just a thin wrapper around isomdl
#[derive(uniffi::Object)]
pub struct MdocIssuer {}

#[uniffi::export]
impl MdocIssuer {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {}
    }
    
    /// Issue an mDoc - isomdl does EVERYTHING
    pub fn issue(
        &self,
        doc_type: String,
        namespaces: HashMap<String, HashMap<String, Vec<u8>>>,
        issuer_cert_pem: String,
        issuer_key_pem: String,
        holder_jwk: String,
    ) -> Result<String, IssuerError> {
        // That's it! isomdl handles:
        // - MSO creation
        // - Signing
        // - Digest computation  
        // - CBOR encoding
        // - Everything else
        Mdoc::create_and_sign(
            doc_type,
            namespaces,
            holder_jwk,
            issuer_cert_pem,
            issuer_key_pem,
        )?
        .stringify()
        .map_err(|e| IssuerError::IssuanceFailed(format!("{:?}", e)))
    }
}