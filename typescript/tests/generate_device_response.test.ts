import * as fs from 'fs';
import * as path from 'path';
import * as cbor from 'cbor';
import { Key, SigAlgs, KeyAlgs } from '@hyperledger/aries-askar-nodejs';
import * as crypto from 'crypto';
import {
    X509CertificateGenerator,
    BasicConstraintsExtension,
    KeyUsagesExtension,
    ExtendedKeyUsageExtension,
    SubjectKeyIdentifierExtension,
    AuthorityKeyIdentifierExtension,
    KeyUsageFlags,
    CRLDistributionPointsExtension,
    IssuerAlternativeNameExtension
} from '@peculiar/x509';

// Use Node's native WebCrypto
const webcrypto = crypto.webcrypto;

const ARTIFACTS_DIR = path.join(__dirname, '../../python/tests/cross_language_artifacts');

describe('Generate Device Response for Python Verification', () => {

    beforeAll(() => {
        if (!fs.existsSync(ARTIFACTS_DIR)) {
            fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
        }
    });

    test('should generate a valid DeviceResponse signed by Credo', async () => {
        const alg = { name: "ECDSA", namedCurve: "P-256" };

        // 1. Generate Root CA
        const rootKeyPair = await webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);

        const rootCert = await X509CertificateGenerator.createSelfSigned({
            serialNumber: "01",
            name: "C=US, CN=Test Root CA",
            notBefore: new Date("2024-01-01"),
            notAfter: new Date("2034-01-01"),
            signingAlgorithm: alg,
            keys: rootKeyPair,
            extensions: [
                new BasicConstraintsExtension(true, 0, true), // CA=true, pathLen=0, critical
                new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
                await SubjectKeyIdentifierExtension.create(rootKeyPair.publicKey),
                new CRLDistributionPointsExtension(["http://example.com/crl"], false),
                new IssuerAlternativeNameExtension([{ type: "url", value: "http://example.com" }], false)
            ]
        });
        const rootCertPem = rootCert.toString("pem");

        // 2. Generate DS Cert
        const dsKeyPair = await webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);

        const dsCert = await X509CertificateGenerator.create({
            serialNumber: "02",
            subject: "C=US, CN=Test DS",
            issuer: rootCert.subject,
            notBefore: new Date("2024-01-01"),
            notAfter: new Date("2026-01-01"),
            signingAlgorithm: alg,
            publicKey: dsKeyPair.publicKey,
            signingKey: rootKeyPair.privateKey,
            extensions: [
                // No BasicConstraints for DS
                new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
                new ExtendedKeyUsageExtension(["1.0.18013.5.1.2"], true), // mDL DS
                await SubjectKeyIdentifierExtension.create(dsKeyPair.publicKey),
                await AuthorityKeyIdentifierExtension.create(rootKeyPair.publicKey),
                new CRLDistributionPointsExtension(["http://example.com/crl"], false),
                new IssuerAlternativeNameExtension([{ type: "url", value: "http://example.com" }], false)
            ]
        });

        const dsCertDer = Buffer.from(dsCert.rawData);
        const issuerPrivateKey = dsKeyPair.privateKey;

        // 3. Generate Device Key (ES256)
        const deviceKey = Key.generate(KeyAlgs.EcSecp256r1);
        const deviceKeyCose = await coseKeyFromAskarKey(deviceKey);

        // 4. Create IssuerSignedItem
        const item = {
            "digestID": 0,
            "random": crypto.randomBytes(16),
            "elementIdentifier": "family_name",
            "elementValue": "Doe"
        };
        const itemBytes = cbor.encodeCanonical(item);
        // Calculate digest
        const itemDigest = crypto.createHash('sha256').update(itemBytes).digest();

        const now = new Date();
        const validUntil = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 365);

        const toTag0 = (date: Date) => {
            return new cbor.Tagged(0, date.toISOString());
        };

        // 5. Create MSO (Mobile Security Object)
        const valueDigests = new Map();
        const nsDigests = new Map();
        nsDigests.set(0, itemDigest);
        valueDigests.set("org.iso.18013.5.1", nsDigests);

        const mso = {
            "version": "1.0",
            "digestAlgorithm": "SHA-256",
            "valueDigests": valueDigests,
            "deviceKeyInfo": {
                "deviceKey": deviceKeyCose
            },
            "docType": "org.iso.18013.5.1.mDL",
            "validityInfo": {
                "signed": toTag0(now),
                "validFrom": toTag0(now),
                "validUntil": toTag0(validUntil)
            }
        };

        const msoBytes = cbor.encodeCanonical(mso);
        const msoTagged = new cbor.Tagged(24, msoBytes);
        const msoTaggedBytes = cbor.encodeCanonical(msoTagged);

        // 6. Sign MSO (IssuerAuth)
        const protectedHeadersMap = new Map();
        protectedHeadersMap.set(1, -7); // alg: ES256
        const protectedHeaders = cbor.encodeCanonical(protectedHeadersMap);

        const unprotectedHeaders = new Map();
        unprotectedHeaders.set(33, [dsCertDer]); // x5chain

        const sigStructure = [
            "Signature1",
            protectedHeaders,
            Buffer.alloc(0), // external_aad
            msoTaggedBytes
        ];

        const toBeSigned = cbor.encodeCanonical(sigStructure);

        const signatureBuffer = await webcrypto.subtle.sign(
            {
                name: "ECDSA",
                hash: { name: "SHA-256" }
            },
            issuerPrivateKey,
            toBeSigned
        );
        const signature = Buffer.from(signatureBuffer);

        const issuerAuth = [
            protectedHeaders,
            unprotectedHeaders,
            msoTaggedBytes,
            signature
        ];

        // 7. Create DeviceSigned
        // SessionTranscript = [DeviceEngagementBytes, ServerRetrievalBytes, Handover]
        // OID4VP Handover = [clientIdHash, responseUriHash, nonce]

        const nonce = "test_nonce_12345";
        const clientId = "https://verifier.example.com";
        const responseUri = "https://verifier.example.com/response/123";

        const clientIdHash = crypto.createHash('sha256').update(clientId).digest();
        const responseUriHash = crypto.createHash('sha256').update(responseUri).digest();

        // OID4VPHandover = [clientIdHash: bstr, responseUriHash: bstr, nonce: tstr]
        const handover = [clientIdHash, responseUriHash, nonce];  // nonce as text string per spec

        // SessionTranscript = [null, null, OID4VPHandover] per OID4VP spec
        const sessionTranscript = [
            null,
            null,
            handover
        ];

        const sessionTranscriptBytes = cbor.encodeCanonical(sessionTranscript);

        // DeviceAuth = [
        //    "DeviceAuthentication",
        //    SessionTranscript,
        //    DocType,
        //    NameSpacesBytes
        // ]
        const docType = "org.iso.18013.5.1.mDL";

        // Prepare IssuerSigned NameSpaces
        // Map<String, List<Tag24<IssuerSignedItem>>>
        const issuerSignedItemBytes = cbor.encodeCanonical(item);
        const issuerSignedItemTagged = new cbor.Tagged(24, issuerSignedItemBytes);

        const issuerNameSpaces = {
            "org.iso.18013.5.1": [ issuerSignedItemTagged ]
        };

        // Prepare DeviceSigned NameSpaces
        // Tag24<Map<String, Map<String, Value>>>
        // We use empty namespaces for DeviceSigned in this test
        const deviceNameSpaces = {};
        const deviceNameSpacesBytes = cbor.encodeCanonical(deviceNameSpaces);
        const deviceNameSpacesTagged = new cbor.Tagged(24, deviceNameSpacesBytes);

        const deviceAuthStructure = [
            "DeviceAuthentication",
            sessionTranscript,
            docType,
            deviceNameSpacesTagged
        ];
        const deviceAuthBytes = cbor.encodeCanonical(deviceAuthStructure);

        // The isomdl library wraps DeviceAuthentication in Tag24 for the detached payload
        // per the COSE detached payload semantics used in ISO 18013-5
        const deviceAuthTag24 = new cbor.Tagged(24, deviceAuthBytes);
        const deviceAuthTag24Bytes = cbor.encodeCanonical(deviceAuthTag24);

        // DeviceAuth COSE_Sign1
        const deviceAuthProtectedMap = new Map();
        deviceAuthProtectedMap.set(1, -7); // alg: ES256
        const deviceAuthProtected = cbor.encodeCanonical(deviceAuthProtectedMap);

        const deviceSigStructure = [
            "Signature1",
            deviceAuthProtected,
            Buffer.alloc(0),
            deviceAuthTag24Bytes  // Use Tag24-wrapped DeviceAuthentication as the detached payload
        ];
        const deviceToBeSigned = cbor.encodeCanonical(deviceSigStructure);

        let deviceSignature = Buffer.from(deviceKey.signMessage({ message: deviceToBeSigned, sigType: SigAlgs.ES256 }));

        // Normalize S if needed (ensure low S)
        // P-256 order n
        const n = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        const r = BigInt("0x" + deviceSignature.subarray(0, 32).toString('hex'));
        let s = BigInt("0x" + deviceSignature.subarray(32, 64).toString('hex'));

        if (s > n / 2n) {
            console.log("Normalizing signature S");
            s = n - s;
            const rBuffer = Buffer.from(r.toString(16).padStart(64, '0'), 'hex');
            const sBuffer = Buffer.from(s.toString(16).padStart(64, '0'), 'hex');
            deviceSignature = Buffer.concat([rBuffer, sBuffer]);
        }

        // Verify with WebCrypto
        const importedKey = await webcrypto.subtle.importKey(
            "jwk",
            deviceKey.jwkPublic,
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["verify"]
        );

        const valid = await webcrypto.subtle.verify(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            importedKey,
            deviceSignature,
            deviceToBeSigned
        );
        console.log("Signature Valid (TS WebCrypto):", valid);

        const deviceAuthCose = [
            deviceAuthProtected,
            {}, // unprotected
            null, // payload is detached
            deviceSignature
        ];

        const deviceSigned = {
            "nameSpaces": deviceNameSpacesTagged, // Tagged
            "deviceAuth": {
                "deviceSignature": deviceAuthCose
            }
        };

        // 8. Assemble DeviceResponse
        const deviceResponse = {
            "version": "1.0",
            "documents": [
                {
                    "docType": docType,
                    "issuerSigned": {
                        "nameSpaces": issuerNameSpaces, // Map (not Tagged)
                        "issuerAuth": issuerAuth
                    },
                    "deviceSigned": deviceSigned
                }
            ],
            "status": 0
        };

        const deviceResponseBytes = cbor.encodeCanonical(deviceResponse);

        // 8. Save Artifacts
        fs.writeFileSync(path.join(ARTIFACTS_DIR, 'device_response.cbor'), deviceResponseBytes);
        fs.writeFileSync(path.join(ARTIFACTS_DIR, 'issuer_cert.pem'), rootCertPem);

        // Also save params for Python to use
        const params = {
            nonce,
            clientId,
            responseUri
        };
        fs.writeFileSync(path.join(ARTIFACTS_DIR, 'oid4vp_params.json'), JSON.stringify(params));
    });
});

async function coseKeyFromAskarKey(key: Key): Promise<Map<number, any>> {
    const jwk = key.jwkPublic;
    // Convert JWK to COSE_Key Map
    // kty: 2 (EC2) -> 1: 2
    // crv: P-256 -> -1: 1
    // x -> -2: Buffer
    // y -> -3: Buffer

    const coseKey = new Map();
    coseKey.set(1, 2); // kty: EC2
    coseKey.set(-1, 1); // crv: P-256
    coseKey.set(-2, Buffer.from(jwk.x!, 'base64url'));
    coseKey.set(-3, Buffer.from(jwk.y!, 'base64url'));

    return coseKey;
}
