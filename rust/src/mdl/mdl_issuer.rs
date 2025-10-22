use std::collections::HashMap;
use serde_json::{json, Value};

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum MdlError {
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Issuer error: {0}")]
    IssuerError(String),
    #[error("Verifier error: {0}")]
    VerifierError(String),
    #[error("JSON error: {0}")]
    JsonError(String),
}

/// The absolute simplest MDL API possible
#[derive(uniffi::Object)]
pub struct SimpleMdl {}

#[uniffi::export]
impl SimpleMdl {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {}
    }
    
    /// Issue an MDL from a JSON object - that's it!
    pub fn issue_from_json(
        &self,
        mdl_json: String,
        issuer_cert: String,
        issuer_key: String,
        holder_jwk: String,
    ) -> Result<String, MdlError> {
        // Parse JSON
        let data: Value = serde_json::from_str(&mdl_json)
            .map_err(|e| MdlError::InvalidData(format!("Invalid JSON: {}", e)))?;
        
        // Convert to namespace format (org.iso.18013.5.1 for MDL)
        let mut elements = HashMap::new();
        if let Value::Object(map) = data {
            for (key, val) in map {
                elements.insert(key, serde_json::to_vec(&val).unwrap());
            }
        }
        
        let mut namespaces = HashMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), elements);
        
        // Issue using isomdl
        let issuer = crate::mdl::issuer::MdocIssuer::new();
        issuer.issue(
            "org.iso.18013.5.1.mDL".to_string(),
            namespaces,
            issuer_cert,
            issuer_key,
            holder_jwk,
        ).map_err(|e| MdlError::IssuerError(format!("{:?}", e)))
    }
    
    /// Verify an MDL with trust anchors and get back JSON
    pub fn verify_to_json(
        &self, 
        mdl_string: String,
        trust_anchor_pems: Vec<String>,
    ) -> Result<String, MdlError> {
        let verifier = crate::mdl::verifier::MdocVerifier::new();
        let result = verifier.verify(mdl_string, trust_anchor_pems)
            .map_err(|e| MdlError::VerifierError(format!("{:?}", e)))?;
        
        // Convert result to JSON
        let json_result = json!({
            "valid": result.valid,
            "doc_type": result.doc_type,
            "data": result.data.get("\"org.iso.18013.5.1\"")
        });
        
        serde_json::to_string_pretty(&json_result)
            .map_err(|e| MdlError::JsonError(format!("JSON error: {}", e)))
    }
    
    /// Verify without trust anchors (structure only)
    pub fn verify_structure_to_json(&self, mdl_string: String) -> Result<String, MdlError> {
        self.verify_to_json(mdl_string, vec![])
    }
    
    /// The simplest possible MDL issuance - just the required fields
    pub fn issue_basic(
        &self,
        family_name: String,
        given_name: String,
        birth_date: String,
        document_number: String,
        issuer_cert: String,
        issuer_key: String,
        holder_jwk: String,
    ) -> Result<String, MdlError> {
        let mdl_json = json!({
            "family_name": family_name,
            "given_name": given_name,
            "birth_date": birth_date,
            "document_number": document_number,
            "issuing_country": "US",
            "issuing_authority": "DMV",
            "issue_date": "20240101",
            "expiry_date": "20290101"
        });
        
        self.issue_from_json(
            mdl_json.to_string(),
            issuer_cert,
            issuer_key,
            holder_jwk,
        )
    }
}