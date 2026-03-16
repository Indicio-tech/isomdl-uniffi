use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use ciborium::Value;
use coset::CoseSign1Builder;
use isomdl::{
    cbor,
    cose::sign1::PreparedCoseSign1,
    definitions::{
        DeviceAuth, DeviceResponse, DeviceSigned, Document, IssuerSigned,
        device_response::Status,
        device_signed::{DeviceAuthentication, DeviceNamespaces},
        helpers::{NonEmptyVec, Tag24},
        issuer_signed::IssuerSignedItemBytes,
        traits::ToCbor,
    },
};

use isomdl::definitions::helpers::NonEmptyMap;

use crate::mdl::{
    holder::{ResponseError, SignatureError},
    mdoc::{Mdoc, convert_namespaces},
    reader::{OID4VPHandover, OID4VPHandoverInfo, OID4VPSessionTranscript},
};

// ── Internal structs for deserialising an OID4VP authorisation request ────────

#[derive(serde::Deserialize)]
struct Oid4vpRequest {
    client_id: String,
    nonce: String,
    response_uri: String,
    presentation_definition: PresentationDefinition,
}

#[derive(serde::Deserialize)]
struct PresentationDefinition {
    input_descriptors: Vec<InputDescriptor>,
}

#[derive(serde::Deserialize)]
struct InputDescriptor {
    constraints: Constraints,
}

#[derive(serde::Deserialize)]
struct Constraints {
    fields: Vec<Field>,
}

#[derive(serde::Deserialize)]
struct Field {
    path: Vec<String>,
}

/// Parses a JSONPath segment of the form `$['namespace']['element']` and returns
/// `(namespace, element_identifier)`, or `None` if the path cannot be parsed.
fn parse_mdoc_path(path: &str) -> Option<(String, String)> {
    // Strip leading `$` then collect all `['...']` segments.
    let rest = path.strip_prefix('$')?;
    let mut segments = Vec::new();
    let mut remaining = rest;
    while let Some(start) = remaining.find("['") {
        let inner = &remaining[start + 2..];
        let end = inner.find("']")?;
        segments.push(inner[..end].to_string());
        remaining = &inner[end + 2..];
    }
    if segments.len() == 2 {
        Some((segments.remove(0), segments.remove(0)))
    } else {
        None
    }
}

/// The result of parsing an OID4VP authorisation request.
#[derive(uniffi::Record)]
pub struct ParsedOid4vpRequest {
    /// JSON-serialised `OID4VPSessionTranscript` ready to pass to
    /// `MDocOid4vpSession::build_device_response`.
    pub session_transcript_json: String,
    /// Map of `namespace → { element_identifier → CBOR-encoded placeholder }`
    /// ready to pass as `permitted_namespaces` to `build_device_response`.
    /// Values are CBOR-null placeholders; only the keys are used for filtering.
    pub permitted_namespaces: HashMap<String, HashMap<String, Vec<u8>>>,
}

#[derive(uniffi::Object)]
pub struct MDocOid4vpSession {
    mdoc: Arc<Mdoc>,
}

#[uniffi::export]
impl MDocOid4vpSession {
    #[uniffi::constructor]
    pub fn new(mdoc: Arc<Mdoc>) -> Self {
        Self { mdoc }
    }

    /// Parses an OID4VP 1.0 authorisation request JSON string and returns a
    /// ready-to-use session transcript and permitted-namespaces map.
    ///
    /// The session transcript is built from `client_id`, `nonce`, and
    /// `response_uri` following OpenID4VP Appendix B.2.6.1.
    ///
    /// `permitted_namespaces` is derived from
    /// `presentation_definition.input_descriptors[].constraints.fields[].path`
    /// where each path has the form `$['namespace']['element_identifier']`.
    pub fn parse_authorization_request(
        &self,
        request_json: String,
    ) -> Result<ParsedOid4vpRequest, ResponseError> {
        use sha2::{Digest, Sha256};

        let req: Oid4vpRequest =
            serde_json::from_str(&request_json).map_err(|e| ResponseError::Generic {
                value: format!("Failed to parse OID4VP request JSON: {e}"),
            })?;

        // ── Session transcript ─────────────────────────────────────────────
        // OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
        // jwkThumbprint is null for non-encrypted responses.
        let handover_info = OID4VPHandoverInfo(
            req.client_id.clone(),
            req.nonce.clone(),
            None,
            req.response_uri.clone(),
        );

        let mut handover_info_bytes = Vec::new();
        ciborium::into_writer(&handover_info, &mut handover_info_bytes).map_err(|e| {
            ResponseError::Generic {
                value: format!("Failed to CBOR-encode handover info: {e}"),
            }
        })?;

        let handover_hash = Sha256::digest(&handover_info_bytes).to_vec();

        let transcript = OID4VPSessionTranscript(
            None,
            None,
            OID4VPHandover("OpenID4VPHandover".to_string(), handover_hash),
        );

        let session_transcript_json =
            serde_json::to_string(&transcript).map_err(|e| ResponseError::Generic {
                value: format!("Failed to serialise session transcript: {e}"),
            })?;

        // ── Permitted namespaces ───────────────────────────────────────────
        // Parse each field path, e.g. `$['org.iso.18013.5.1']['given_name']`.
        // Values are CBOR null (0xF6) — only keys are used for element filtering.
        let cbor_null = vec![0xF6u8];
        let mut permitted_namespaces: HashMap<String, HashMap<String, Vec<u8>>> = HashMap::new();

        for descriptor in &req.presentation_definition.input_descriptors {
            for field in &descriptor.constraints.fields {
                for path in &field.path {
                    if let Some((ns, element)) = parse_mdoc_path(path) {
                        permitted_namespaces
                            .entry(ns)
                            .or_default()
                            .entry(element)
                            .or_insert_with(|| cbor_null.clone());
                    }
                }
            }
        }

        Ok(ParsedOid4vpRequest {
            session_transcript_json,
            permitted_namespaces,
        })
    }

    /**
     * Prepares a unsigned oid4vp response
     */
    pub fn build_device_response(
        &self,
        permitted_namespaces: HashMap<String, HashMap<String, Vec<u8>>>,
        session_transcript: String,
    ) -> Result<UnsignedOidvpResponse, ResponseError> {
        let mdoc = self.mdoc.clone();
        let m_doc = mdoc.document();

        let permitted_items =
            convert_namespaces(permitted_namespaces).map_err(|e| ResponseError::Generic {
                value: format!("Error converting namespaces: {e}"),
            })?;

        let device_namespaces =
            Tag24::new(DeviceNamespaces::new()).map_err(|e| ResponseError::Generic {
                value: format!("Error generating namespaces: {e}"),
            })?;

        let transcript: OID4VPSessionTranscript = serde_json::from_str(&session_transcript)
            .map_err(|e| ResponseError::Generic {
                value: format!("Error parsing session transcript: {e}"),
            })?;

        let device_authentication_payload = Tag24::new(DeviceAuthentication::new(
            transcript,
            m_doc.mso.doc_type.clone(),
            device_namespaces.clone(),
        ))
        .map_err(|e| ResponseError::Generic {
            value: format!("Error generating device authentication payload: {e}"),
        })?;

        let device_auth_bytes =
            cbor::to_vec(&device_authentication_payload).map_err(|e| ResponseError::Generic {
                value: format!("Error encoding device authentication payload: {e}"),
            })?;

        let header = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();

        let cose_sign1_builder = CoseSign1Builder::new().protected(header);

        let prepared_cose_sign1 =
            PreparedCoseSign1::new(cose_sign1_builder, Some(&device_auth_bytes), None, false)
                .map_err(|e| ResponseError::Generic {
                    value: format!("Error preparing COSE_Sign1: {e}"),
                })?;

        let device_namespaces_bytes = device_namespaces
            .to_cbor_bytes()
            .map_err(|e| ResponseError::Generic {
                value: format!("Error encoding device namespaces: {e}"),
            })?
            .clone();

        Ok(UnsignedOidvpResponse {
            prepared_cose_sign1,
            mdoc,
            permitted_items,
            device_namespaces_bytes,
        })
    }

    /**
     * Finish constructing the device response by passing the signed payload and the unsigned
     * response returned from `build_device_response`. Returns the CBOR-encoded `DeviceResponse`
     * bytes, which can be passed directly to `verify_oid4vp_response` or base64url-encoded as
     * the `vp_token` in the OID4VP POST body.
     * The signed payload should be the signature bytes from signing the payload returned by
     * `get_signature_payload` on the unsigned response.
     */
    pub fn finish_device_response(
        &self,
        unsigned_response: Arc<UnsignedOidvpResponse>,
        signed_payload: Vec<u8>,
    ) -> Result<Vec<u8>, SignatureError> {
        let mdoc = unsigned_response.mdoc.document();
        let permitted = &unsigned_response.permitted_items;

        let device_signature = unsigned_response
            .prepared_cose_sign1
            .clone()
            .finalize(signed_payload);
        let device_auth = DeviceAuth::DeviceSignature(device_signature);

        let device_namespaces =
            cbor::from_slice::<Tag24<DeviceNamespaces>>(&unsigned_response.device_namespaces_bytes)
                .map_err(|e| SignatureError::Generic {
                    value: format!("Error decoding device namespaces: {e}"),
                })?;

        let device_signed = DeviceSigned {
            namespaces: device_namespaces,
            device_auth,
        };

        let document = Document {
            doc_type: mdoc.mso.doc_type.clone(),
            issuer_signed: IssuerSigned {
                issuer_auth: mdoc.issuer_auth.clone(),
                // Convert mdoc.namespaces (NonEmptyMap<ns, NonEmptyMap<id, Item>>)
                // to IssuerSigned::namespaces (Option<NonEmptyMap<ns, NonEmptyVec<Item>>>),
                // retaining only the element identifiers present in permitted_items.
                namespaces: {
                    let filtered: BTreeMap<String, NonEmptyVec<IssuerSignedItemBytes>> = mdoc
                        .namespaces
                        .iter()
                        .filter_map(|(ns, items)| {
                            let permitted_ns = permitted.get(ns.as_str())?;
                            let vec: Vec<IssuerSignedItemBytes> = items
                                .iter()
                                .filter(|(id, _)| permitted_ns.contains_key(id.as_str()))
                                .map(|(_, item)| item.clone())
                                .collect();
                            NonEmptyVec::maybe_new(vec).map(|v| (ns.clone(), v))
                        })
                        .collect();
                    NonEmptyMap::maybe_new(filtered)
                },
            },
            device_signed,
            errors: None,
        };

        let response = DeviceResponse {
            version: "1.0".to_string(),
            documents: Some(NonEmptyVec::new(document)),
            document_errors: None,
            status: Status::OK,
        };

        cbor::to_vec(&response).map_err(|e| SignatureError::Generic {
            value: format!("Error serializing response to CBOR: {e}"),
        })
    }
}

#[derive(uniffi::Object)]
pub struct UnsignedOidvpResponse {
    pub prepared_cose_sign1: PreparedCoseSign1,
    pub mdoc: Arc<Mdoc>,
    pub permitted_items: BTreeMap<String, BTreeMap<String, Value>>,
    pub device_namespaces_bytes: Vec<u8>,
}

#[uniffi::export]
impl UnsignedOidvpResponse {
    /**
     * Returns the payload that should be signed for the OID4VP response. This is the bytes that should be signed in the COSE_Sign1 structure.
     */
    pub fn get_signature_payload(&self) -> Vec<u8> {
        self.prepared_cose_sign1.signature_payload().to_vec()
    }
}
