//! `handle_response` (the BLE reader path) must surface the presented mdoc's MSO status claim, but
//! only once issuer authentication is `Valid`: before that the MSO is not authenticated.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use isomdl_uniffi::mdl::holder::MdlPresentationSession;
use isomdl_uniffi::mdl::mdoc::Mdoc;
use isomdl_uniffi::mdl::reader::{AuthenticationStatus, establish_session, handle_response};
use isomdl_uniffi::mdl::util::P256KeyPair;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::EncodePem;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

const MDL_NAMESPACE: &str = "org.iso.18013.5.1";
const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
const STATUS: &str = r#"{"status_list":{"idx":42,"uri":"https://example.com/statuslists/1"}}"#;

struct Issuer {
    cert_pem: String,
    key_pem: String,
}

fn issuer() -> Issuer {
    let key = SigningKey::random(&mut OsRng);
    let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap();
    let cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u64),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        "CN=Test Issuer".parse().unwrap(),
        spki,
        &key,
    )
    .unwrap()
    .build::<p256::ecdsa::DerSignature>()
    .unwrap();

    Issuer {
        cert_pem: cert.to_pem(LineEnding::LF).unwrap(),
        key_pem: key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
    }
}

fn mdoc(issuer: &Issuer, holder: &P256KeyPair, status: Option<&str>) -> Arc<Mdoc> {
    let items = serde_json::json!({
        "family_name": "Doe",
        "given_name": "John",
        "birth_date": "1990-01-01",
        "issue_date": "2023-01-01",
        "expiry_date": "2028-01-01",
        "issuing_country": "US",
        "issuing_authority": "DMV",
        "document_number": "123456789",
        "portrait": base64::engine::general_purpose::STANDARD.encode("portrait"),
        "driving_privileges": [{
            "vehicle_category_code": "B",
            "issue_date": "2023-01-01",
            "expiry_date": "2028-01-01"
        }],
        "un_distinguishing_sign": "USA"
    })
    .to_string();

    Mdoc::create_and_sign_mdl(
        items,
        None,
        holder.public_jwk(),
        issuer.cert_pem.clone(),
        issuer.key_pem.clone(),
        status.map(str::to_string),
    )
    .expect("create_and_sign_mdl failed")
}

/// Run a full holder/reader exchange and return the reader's view of the response.
fn exchange(
    mdoc: Arc<Mdoc>,
    holder: &P256KeyPair,
    trust_anchors: Vec<String>,
) -> isomdl_uniffi::mdl::reader::MDLReaderResponseData {
    let uuid = uuid::Uuid::new_v4().to_string();
    let presentation = MdlPresentationSession::new(mdoc, uuid).expect("holder session");

    let requested = HashMap::from([(
        MDL_NAMESPACE.to_string(),
        HashMap::from([("given_name".to_string(), false)]),
    )]);
    let reader = establish_session(
        presentation.get_qr_code_uri(),
        requested,
        Some(trust_anchors),
    )
    .expect("reader session");

    presentation
        .handle_request(reader.request.clone())
        .expect("holder handles request");
    let payload = presentation
        .generate_response(HashMap::from([(
            DOC_TYPE.to_string(),
            HashMap::from([(MDL_NAMESPACE.to_string(), vec!["given_name".to_string()])]),
        )]))
        .expect("holder prepares response");
    let response = presentation
        .submit_response(holder.sign(&payload))
        .expect("holder signs response");

    handle_response(reader.state.clone(), response).expect("reader handles response")
}

/// The status claim is reported exactly when the issuer was authenticated.
///
/// NOTE: the generated test issuer does not satisfy isomdl's mDL certificate profile (it needs an
/// IACA with CRL distribution points, an issuer alternative name, `path_len` 0, and a matching
/// country), so issuer authentication is `Invalid` here and this exercises the withheld side. The
/// `Valid` side needs a profile-compliant IACA and document signer; until one is added it is
/// covered only by testing with a real credential. The assertion holds for either outcome.
#[test]
fn status_list_is_reported_iff_issuer_authentication_is_valid() {
    let issuer = issuer();
    let holder = P256KeyPair::new();

    let data = exchange(
        mdoc(&issuer, &holder, Some(STATUS)),
        &holder,
        vec![issuer.cert_pem.clone()],
    );

    assert_eq!(data.device_authentication, AuthenticationStatus::Valid);
    assert_eq!(
        data.status_list.is_some(),
        data.issuer_authentication == AuthenticationStatus::Valid,
        "status_list must be reported iff issuer authentication is Valid (issuer auth: {:?}, errors: {:?})",
        data.issuer_authentication,
        data.errors,
    );
    if let Some(status) = data.status_list {
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&status).unwrap(),
            serde_json::from_str::<serde_json::Value>(STATUS).unwrap()
        );
    }
}

/// With no trust anchor the issuer cannot be authenticated, so the (unauthenticated) status claim
/// must be withheld.
#[test]
fn status_list_is_withheld_when_the_issuer_is_not_authenticated() {
    let issuer = issuer();
    let holder = P256KeyPair::new();

    let data = exchange(mdoc(&issuer, &holder, Some(STATUS)), &holder, vec![]);

    assert_eq!(data.issuer_authentication, AuthenticationStatus::Invalid);
    assert_eq!(data.status_list, None);
}

#[test]
fn credential_without_a_status_claim_reports_none() {
    let issuer = issuer();
    let holder = P256KeyPair::new();

    let data = exchange(
        mdoc(&issuer, &holder, None),
        &holder,
        vec![issuer.cert_pem.clone()],
    );

    assert_eq!(data.status_list, None);
}
