//https://github.com/spruceid/sprucekit-mobile/blob/main/rust/src/mdl/holder.rs

use isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry;
use isomdl::{
    definitions::{
        BleOptions, DeviceRetrievalMethod, SessionEstablishment,
        device_engagement::{CentralClientMode, DeviceRetrievalMethods},
        helpers::NonEmptyMap,
        session,
    },
    presentation::device::{self, SessionManagerInit},
};

use std::ops::DerefMut;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

use super::mdoc::Mdoc;

#[derive(uniffi::Object)]
pub struct MdlPresentationSession {
    engaged: Mutex<device::SessionManagerEngaged>,
    in_process: Mutex<Option<InProcessRecord>>,
    pub qr_code_uri: String,
    pub ble_ident: Vec<u8>,
}

#[derive(uniffi::Object, Clone)]
struct InProcessRecord {
    session: device::SessionManager,
    items_request: device::RequestedItems,
}

#[uniffi::export]
impl MdlPresentationSession {
    /// Begin the mDL presentation process for the holder by passing in the credential
    /// to be presented in the form of an [Mdoc] object.
    ///
    /// Initializes the presentation session for an ISO 18013-5 mDL and stores
    /// the session state object in the device storage_manager.
    ///
    /// Arguments:
    /// mdoc: the Mdoc to be presented, as an [Mdoc] object
    /// uuid: the Bluetooth Low Energy Client Central Mode UUID to be used
    ///
    /// Returns:
    /// A Result, with the `Ok` containing a tuple consisting of an enum representing
    /// the state of the presentation, a String containing the QR code URI, and a
    /// String containing the BLE ident.
    ///
    #[uniffi::constructor]
    pub fn new(mdoc: Arc<Mdoc>, uuid: Uuid) -> Result<MdlPresentationSession, SessionError> {
        let drms = DeviceRetrievalMethods::new(DeviceRetrievalMethod::BLE(BleOptions {
            peripheral_server_mode: None,
            central_client_mode: Some(CentralClientMode { uuid }),
        }));
        let session = SessionManagerInit::initialise(
            NonEmptyMap::new("org.iso.18013.5.1.mDL".into(), mdoc.document().clone()),
            Some(drms),
            None,
        )
        .map_err(|e| SessionError::Generic {
            value: format!("Could not initialize session: {e:?}"),
        })?;
        let ble_ident = session
            .ble_ident()
            .map_err(|e| SessionError::Generic {
                value: format!("Couldn't get BLE identification: {e:?}").to_string(),
            })?
            .to_vec();
        let (engaged_state, qr_code_uri) =
            session.qr_engagement().map_err(|e| SessionError::Generic {
                value: format!("Could not generate qr engagement: {e:?}"),
            })?;
        Ok(MdlPresentationSession {
            engaged: Mutex::new(engaged_state),
            in_process: Mutex::new(None),
            qr_code_uri,
            ble_ident,
        })
    }

    /// Handle a request from a reader that is seeking information from the mDL holder.
    ///
    /// Takes the raw bytes received from the reader by the holder over the transmission
    /// technology. Returns a Vector of information items requested by the reader, or an
    /// error.
    pub fn handle_request(&self, request: Vec<u8>) -> Result<Vec<ItemsRequest>, RequestError> {
        let (session_manager, items_requests) = {
            let session_establishment: SessionEstablishment = isomdl::cbor::from_slice(&request)
                .map_err(|e| RequestError::Generic {
                    value: format!("Could not deserialize request: {e:?}"),
                })?;
            self.engaged
                .lock()
                .map_err(|_| RequestError::Generic {
                    value: "Could not lock mutex".to_string(),
                })?
                .clone()
                .process_session_establishment(
                    session_establishment,
                    TrustAnchorRegistry::default(),
                )
                .map_err(|e| RequestError::Generic {
                    value: format!("Could not process process session establishment: {e:?}"),
                })?
        };

        let mut in_process = self.in_process.lock().map_err(|_| RequestError::Generic {
            value: "Could not lock mutex".to_string(),
        })?;
        *in_process = Some(InProcessRecord {
            session: session_manager,
            items_request: items_requests.items_request.clone(),
        });

        Ok(items_requests
            .items_request
            .into_iter()
            .map(|req| ItemsRequest {
                doc_type: req.doc_type,
                namespaces: req
                    .namespaces
                    .into_inner()
                    .into_iter()
                    .map(|(ns, es)| {
                        let items_request = es.into_inner().into_iter().collect();
                        (ns, items_request)
                    })
                    .collect(),
            })
            .collect())
    }

    /// Constructs the response to be sent from the holder to the reader containing
    /// the items of information the user has consented to share.
    ///
    /// Takes a HashMap of items the user has authorized the app to share, as well
    /// as the id of a key stored in the key manager to be used to sign the response.
    /// Returns a byte array containing the signed response to be returned to the
    /// reader.
    pub fn generate_response(
        &self,
        permitted_items: HashMap<String, HashMap<String, Vec<String>>>,
    ) -> Result<Vec<u8>, SignatureError> {
        let permitted = permitted_items
            .into_iter()
            .map(|(doc_type, namespaces)| {
                let ns = namespaces.into_iter().collect();
                (doc_type, ns)
            })
            .collect();
        if let Some(in_process) = self.in_process.lock().unwrap().deref_mut() {
            in_process
                .session
                .prepare_response(&in_process.items_request, permitted);
            Ok(in_process
                .session
                .get_next_signature_payload()
                .map(|(_, payload)| payload)
                .ok_or(SignatureError::Generic {
                    value: "Failed to get next signature payload".to_string(),
                })?
                .to_vec())
        } else {
            Err(SignatureError::Generic {
                value: "Could not get lock on session".to_string(),
            })
        }
    }

    pub fn submit_response(&self, signature: Vec<u8>) -> Result<Vec<u8>, SignatureError> {
        let signature = p256::ecdsa::Signature::from_slice(&signature).map_err(|e| {
            SignatureError::InvalidSignature {
                value: e.to_string(),
            }
        })?;
        if let Some(in_process) = self.in_process.lock().unwrap().deref_mut() {
            in_process
                .session
                .submit_next_signature(signature.to_bytes().to_vec())
                .map_err(|e| SignatureError::Generic {
                    value: format!("Could not submit next signature: {e:?}"),
                })?;
            in_process
                .session
                .retrieve_response()
                .ok_or(SignatureError::TooManyDocuments)
        } else {
            Err(SignatureError::Generic {
                value: "Could not get lock on session".to_string(),
            })
        }
    }

    /// Terminates the mDL exchange session.
    ///
    /// Returns the termination message to be transmitted to the reader.
    pub fn terminate_session(&self) -> Result<Vec<u8>, TerminationError> {
        let msg = session::SessionData {
            data: None,
            status: Some(session::Status::SessionTermination),
        };
        let msg_bytes = isomdl::cbor::to_vec(&msg).map_err(|e| TerminationError::Generic {
            value: format!("Could not serialize message bytes: {e:?}"),
        })?;
        Ok(msg_bytes)
    }

    /// Returns the generated QR code
    pub fn get_qr_code_uri(&self) -> String {
        self.qr_code_uri.clone()
    }

    /// Returns the BLE identification
    pub fn get_ble_ident(&self) -> Vec<u8> {
        self.ble_ident.clone()
    }
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum SessionError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum RequestError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Record, Clone)]
pub struct ItemsRequest {
    doc_type: String,
    namespaces: HashMap<String, HashMap<String, bool>>,
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum ResponseError {
    #[error("no signature payload received from session manager")]
    MissingSignature,
    #[error("{value}")]
    Generic { value: String },
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum SignatureError {
    #[error("Invalid DER signature: {value}")]
    InvalidSignature { value: String },
    #[error("there were more documents to sign, but we only expected to sign 1!")]
    TooManyDocuments,
    #[error("{value}")]
    Generic { value: String },
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum TerminationError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum KeyTransformationError {
    #[error("{value}")]
    ToPKCS8 { value: String },
    #[error("{value}")]
    FromPKCS8 { value: String },
    #[error("{value}")]
    FromSEC1 { value: String },
    #[error("{value}")]
    ToSEC1 { value: String },
}
