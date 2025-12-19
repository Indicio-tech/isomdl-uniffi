use isomdl::definitions::helpers::NonEmptyMap;
use isomdl::definitions::namespaces::org_iso_18013_5_1::OrgIso1801351;
use isomdl::definitions::traits::{FromJson, ToNamespaceMap};
use isomdl::definitions::x509::X5Chain;
use isomdl::definitions::{CoseKey, DeviceKeyInfo, DigestAlgorithm, EC2Curve, EC2Y, ValidityInfo};
use isomdl::issuance::Mdoc as IssuanceMdoc;
use isomdl::presentation::device::Document;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::EncodePrivateKey;
use rand_core::OsRng;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::EncodePem;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

#[test]
fn test_intermediate_chaining() {
    // 1. Generate keys
    let root_key = SigningKey::random(&mut OsRng);
    let intermediate_key = SigningKey::random(&mut OsRng);

    // 2. Generate Certificates
    // Root
    let root_name: Name = "CN=Root".parse().unwrap();
    let root_spki = SubjectPublicKeyInfoOwned::from_key(root_key.verifying_key().clone()).unwrap();
    let root_builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u64),
        Validity::from_now(StdDuration::from_secs(365 * 24 * 60 * 60)).unwrap(),
        root_name.clone(),
        root_spki,
        &root_key,
    )
    .unwrap();
    let root_cert = root_builder.build::<p256::ecdsa::DerSignature>().unwrap();

    // Intermediate
    let int_name: Name = "CN=Intermediate".parse().unwrap();
    let int_spki =
        SubjectPublicKeyInfoOwned::from_key(intermediate_key.verifying_key().clone()).unwrap();

    let int_builder = CertificateBuilder::new(
        Profile::SubCA {
            issuer: root_name.clone(),
            path_len_constraint: None,
        },
        SerialNumber::from(2u64),
        Validity::from_now(StdDuration::from_secs(365 * 24 * 60 * 60)).unwrap(),
        int_name,
        int_spki,
        &root_key, // Signed by Root
    )
    .unwrap();

    let intermediate_cert = int_builder.build::<p256::ecdsa::DerSignature>().unwrap();

    // 3. Prepare PEMs
    let root_pem = root_cert
        .to_pem(x509_cert::der::pem::LineEnding::LF)
        .unwrap();
    let intermediate_pem = intermediate_cert
        .to_pem(x509_cert::der::pem::LineEnding::LF)
        .unwrap();

    let chain_pem = format!("{}{}", intermediate_pem, root_pem);
    let intermediate_key_pem = intermediate_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();

    // 4. Use setup_certificate_chain
    use isomdl_uniffi::mdl::util::setup_certificate_chain;

    let (ds_cert, iaca_certs, ds_key) = setup_certificate_chain(chain_pem, intermediate_key_pem)
        .expect("Failed to setup certificate chain");

    // 5. Create Document using Mdoc builder
    let device_key = SigningKey::random(&mut OsRng);
    let device_pub_key = VerifyingKey::from(&device_key);

    let ec = device_pub_key.to_encoded_point(false);
    let x = ec.x().unwrap().to_vec();
    let y = EC2Y::Value(ec.y().unwrap().to_vec());
    let device_cose_key = CoseKey::EC2 {
        crv: EC2Curve::P256,
        x,
        y,
    };

    let device_key_info = DeviceKeyInfo {
        device_key: device_cose_key,
        key_authorizations: None,
        key_info: None,
    };

    let validity_info = ValidityInfo {
        signed: OffsetDateTime::now_utc(),
        valid_from: OffsetDateTime::now_utc(),
        valid_until: OffsetDateTime::now_utc() + Duration::days(30),
        expected_update: None,
    };

    let digest_algorithm = DigestAlgorithm::SHA256;
    let doc_type = "org.iso.18013.5.1.mDL".to_string();

    let isomdl_data = json!({
        "family_name": "Smith",
        "given_name": "Alice",
        "birth_date": "1980-01-01",
        "issue_date": "2020-01-01",
        "expiry_date": "2030-01-01",
        "issuing_country": "US",
        "issuing_authority": "NY DMV",
        "document_number": "DL12345678",
        "portrait": "SGVsbG8gV29ybGQ=",
        "driving_privileges": [
            {
                "vehicle_category_code": "B",
                "issue_date": "2020-01-01",
                "expiry_date": "2030-01-01"
            }
        ],
        "un_distinguishing_sign": "USA"
    });

    let isomdl_ns_data = OrgIso1801351::from_json(&isomdl_data).unwrap().to_ns_map();
    let mut namespaces = BTreeMap::new();
    namespaces.insert("org.iso.18013.5.1".to_string(), isomdl_ns_data);

    let builder = IssuanceMdoc::builder()
        .device_key_info(device_key_info)
        .digest_algorithm(digest_algorithm)
        .validity_info(validity_info)
        .doc_type(doc_type)
        .namespaces(namespaces);

    let mut x5chain_builder = X5Chain::builder()
        .with_certificate(ds_cert)
        .expect("Failed to add DS cert");

    for cert in iaca_certs {
        x5chain_builder = x5chain_builder
            .with_certificate(cert)
            .expect("Failed to add IACA cert");
    }

    let x5chain = x5chain_builder.build().expect("Failed to build X5Chain");

    let mdoc = builder
        .issue::<p256::ecdsa::SigningKey, p256::ecdsa::Signature>(x5chain, ds_key)
        .expect("Failed to issue mdoc");

    // 6. Convert to Document
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
                .ok_or("Empty inner map".to_string())?;
                Ok((namespace, inner_map))
            })
            .collect::<Result<_, String>>()
            .unwrap(),
    )
    .ok_or("Empty namespaces".to_string())
    .unwrap();

    let doc = Document {
        id: Default::default(),
        issuer_auth: mdoc.issuer_auth,
        mso: mdoc.mso,
        namespaces,
    };

    // 7. Verify
    let mut cbor_buffer = Vec::new();
    ciborium::into_writer(&doc, &mut cbor_buffer).unwrap();

    let mdoc_wrapper = isomdl_uniffi::mdl::mdoc::Mdoc::from_cbor_encoded_document(
        cbor_buffer,
        isomdl_uniffi::mdl::mdoc::KeyAlias("test".to_string()),
    )
    .unwrap();

    // We verify without trust anchors first to check the chain structure
    let result = mdoc_wrapper.verify_issuer_signature(None, false);
    assert!(result.is_ok(), "Verification failed: {:?}", result);

    let verification = result.unwrap();
    assert!(verification.verified, "Signature should be valid");
}
