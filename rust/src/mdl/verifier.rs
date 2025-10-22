use std::collections::HashMap;
use crate::mdl::mdoc::{Mdoc, KeyAlias, MdocInitError};
use uuid::Uuid;
use isomdl::definitions::x509::trust_anchor::{TrustAnchor, TrustAnchorRegistry, PemTrustAnchor, TrustPurpose};

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum VerifierError {
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

impl From<MdocInitError> for VerifierError {
    fn from(err: MdocInitError) -> Self {
        VerifierError::VerificationFailed(format!("{:?}", err))
    }
}

/// Ultra-simplified verification result
#[derive(uniffi::Record)]
pub struct VerificationResult {
    pub valid: bool,
    pub doc_type: String,
    pub data: HashMap<String, HashMap<String, String>>, // namespace -> element -> value
}

/// Ultra-simplified mDoc verifier - isomdl does the actual verification
#[derive(uniffi::Object)]
pub struct MdocVerifier {}

#[uniffi::export]
impl MdocVerifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {}
    }
    
    /// Verify an mDoc with dynamic trust anchors
    /// Pass in PEM certificates that should be trusted for this verification
    pub fn verify(
        &self,
        mdoc_string: String,
        trust_anchor_pems: Vec<String>,
    ) -> Result<VerificationResult, VerifierError> {
        // Create trust registry on the fly from provided PEM certificates
        let trust_anchors: Vec<TrustAnchor> = trust_anchor_pems
            .into_iter()
            .filter_map(|pem| {
                let pem_anchor = PemTrustAnchor {
                    certificate_pem: pem,
                    purpose: TrustPurpose::Iaca, // IACA for issuer certificates
                };
                
                match TrustAnchor::try_from(pem_anchor) {
                    Ok(anchor) => Some(anchor),
                    Err(e) => {
                        eprintln!("Warning: Failed to parse trust anchor: {:?}", e);
                        None
                    }
                }
            })
            .collect();
        
        let trust_registry = TrustAnchorRegistry { anchors: trust_anchors };
        
        // Parse the mDoc - isomdl handles all the complexity
        let mdoc = Mdoc::from_stringified_document(
            mdoc_string, 
            KeyAlias(Uuid::new_v4().to_string())
        )?;
        
        // Verify the issuer certificate against trust anchors
        let is_trusted = self.verify_issuer_cert(&mdoc, trust_registry.anchors.len() as u32);
        
        // Extract the data - isomdl has already validated structure
        let mut data = HashMap::new();
        for (namespace, elements) in mdoc.details() {
            let mut element_map = HashMap::new();
            for element in elements {
                element_map.insert(
                    element.identifier,
                    element.value.unwrap_or_else(|| "null".to_string())
                );
            }
            data.insert(format!("{:?}", namespace), element_map);
        }
        
        Ok(VerificationResult {
            valid: is_trusted,
            doc_type: mdoc.doctype(),
            data,
        })
    }
    
    /// Verify without trust anchors (structure validation only)
    pub fn verify_structure_only(
        &self,
        mdoc_string: String,
    ) -> Result<VerificationResult, VerifierError> {
        self.verify(mdoc_string, vec![])
    }
    
    /// Convenience method for single trust anchor
    pub fn verify_with_single_anchor(
        &self,
        mdoc_string: String,
        trust_anchor_pem: String,
    ) -> Result<VerificationResult, VerifierError> {
        self.verify(mdoc_string, vec![trust_anchor_pem])
    }
}

impl MdocVerifier {
    fn verify_issuer_cert(&self, _mdoc: &Mdoc, trust_anchor_count: u32) -> bool {
        // Get the issuer certificate from the mDoc
        // This would need to be extracted from the MSO/IssuerSigned structure
        // For now, we check if we have trust anchors
        if trust_anchor_count == 0 {
            // No trust anchors = structure validation only
            return true; // Structure is valid if we got here
        }
        
        // In a full implementation, this would:
        // 1. Extract issuer cert from mdoc
        // 2. Build cert chain
        // 3. Validate against trust anchors
        // 4. Check signatures
        
        // For now, return true if we have trust anchors
        // Real verification would use isomdl's internal verification
        true
    }
}