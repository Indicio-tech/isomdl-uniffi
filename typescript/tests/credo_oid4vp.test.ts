
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

describe('Credo OID4VP Compatibility Tests', () => {

    beforeAll(() => {
        if (!fs.existsSync(ARTIFACTS_DIR)) {
            fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
        }
    });

    test('should generate a spec-compliant OID4VP DeviceResponse using Credo/Askar keys', async () => {
        const alg = { name: "ECDSA", namedCurve: "P-256" };

        // 1. Setup PKI (Mock Issuer)
        const rootKeyPair = await webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
        const rootCert = await X509CertificateGenerator.createSelfSigned({
            serialNumber: "01",
            name: "C=US, CN=Test Root CA",
            notBefore: new Date("2024-01-01"),
            notAfter: new Date("2034-01-01"),
            signingAlgorithm: alg,
            keys: rootKeyPair,
            extensions: [
                new BasicConstraintsExtension(true, 0, true),
                new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
                await SubjectKeyIdentifierExtension.create(rootKeyPair.publicKey),
                new CRLDistributionPointsExtension(["http://example.com/crl"], false),
                new IssuerAlternativeNameExtension([{ type: "url", value: "http://example.com" }], false)
            ]
        });
        const rootCertPem = rootCert.toString("pem");

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
                new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
                new ExtendedKeyUsageExtension(["1.0.18013.5.1.2"], true),
                await SubjectKeyIdentifierExtension.create(dsKeyPair.publicKey),
                await AuthorityKeyIdentifierExtension.create(rootKeyPair.publicKey),
                new CRLDistributionPointsExtension(["http://example.com/crl"], false),
                new IssuerAlternativeNameExtension([{ type: "url", value: "http://example.com" }], false)
            ]
        });

        const dsCertDer = Buffer.from(dsCert.rawData);
        const issuerPrivateKey = dsKeyPair.privateKey;

        // 2. Generate Device Key using Askar (Credo)
        const deviceKey = Key.generate(KeyAlgs.EcSecp256r1);
        const deviceKeyCose = await coseKeyFromAskarKey(deviceKey);

        // 3. Create MSO (Mobile Security Object)
        const item = {
            "digestID": 0,
            "random": crypto.randomBytes(16),
            "elementIdentifier": "family_name",
            "elementValue": "Doe"
        };
        const itemBytes = cbor.encodeCanonical(item);
        const itemDigest = crypto.createHash('sha256').update(itemBytes).digest();

        const now = new Date();
        const validUntil = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 365); // 1 year

        const mso = {
            "version": "1.0",
            "digestAlgorithm": "SHA-256",
            "valueDigests": {
                "org.iso.18013.5.1": new Map([
                    [0, itemDigest]
                ])
            },
            "deviceKeyInfo": {
                "deviceKey": deviceKeyCose
            },
            "docType": "org.iso.18013.5.1.mDL",
            "validityInfo": {
                "signed": new cbor.Tagged(0, now.toISOString()),
                "validFrom": new cbor.Tagged(0, now.toISOString()),
                "validUntil": new cbor.Tagged(0, validUntil.toISOString())
            }
        };
        const msoBytes = cbor.encodeCanonical(mso);
        // MSO must be wrapped in Tag24 for signing
        const msoTagged = new cbor.Tagged(24, msoBytes);
        const msoTaggedBytes = cbor.encodeCanonical(msoTagged);

        // 4. Sign MSO (Issuer Signature)
        const msoHeader = new Map();
        msoHeader.set(1, -7); // alg: ES256
        const protectedHeader = cbor.encodeCanonical(msoHeader);

        const unprotectedHeader = new Map();
        unprotectedHeader.set(33, [Buffer.from(dsCert.rawData)]); // x5chain (array of bytes)

        const sigStructure = [
            "Signature1",
            protectedHeader,
            Buffer.alloc(0),
            msoTaggedBytes
        ];
        const toBeSigned = cbor.encodeCanonical(sigStructure);
        const signature = await webcrypto.subtle.sign(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            issuerPrivateKey,
            toBeSigned
        );

        let issuerSignature = Buffer.from(signature);
        // Normalize S (Low S) for Issuer Signature
        const n = Buffer.from("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", "hex");
        const halfN = Buffer.from("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", "hex");

        const rIssuer = issuerSignature.subarray(0, 32);
        let sIssuer = issuerSignature.subarray(32, 64);

        let sIssuerBig = BigInt("0x" + sIssuer.toString('hex'));
        let nBig = BigInt("0x" + n.toString('hex'));
        let halfNBig = BigInt("0x" + halfN.toString('hex'));

        if (sIssuerBig > halfNBig) {
            sIssuerBig = nBig - sIssuerBig;
            sIssuer = Buffer.from(sIssuerBig.toString(16).padStart(64, '0'), 'hex');
            issuerSignature = Buffer.concat([rIssuer, sIssuer]);
        }

        const issuerAuth = [
            protectedHeader,
            unprotectedHeader, // unprotected
            msoTaggedBytes,
            issuerSignature
        ];

        // 5. Construct DeviceResponse with OID4VP SessionTranscript
        const nonce = "test_nonce_oid4vp";
        const clientId = "client_id_oid4vp";
        const responseUri = "response_uri_oid4vp";

        const clientIdHash = crypto.createHash('sha256').update(clientId).digest();
        const responseUriHash = crypto.createHash('sha256').update(responseUri).digest();

        // OID4VP Handover: [clientIdHash, responseUriHash, nonce]
        // Nonce must be a text string (tstr) per OID4VP spec
        const handover = [clientIdHash, responseUriHash, nonce];

        // SessionTranscript: [null, null, Handover] per OID4VP spec
        const sessionTranscript = [
            null,
            null,
            handover
        ];
        const sessionTranscriptBytes = cbor.encodeCanonical(sessionTranscript);

        // 6. Create DeviceSigned
        const deviceNameSpaces = {};
        const deviceNameSpacesBytes = cbor.encodeCanonical(deviceNameSpaces);
        const deviceNameSpacesTagged = new cbor.Tagged(24, deviceNameSpacesBytes);

        const deviceAuthStructure = [
            "DeviceAuthentication",
            sessionTranscript,
            "org.iso.18013.5.1.mDL",
            deviceNameSpacesTagged
        ];
        const deviceAuthBytes = cbor.encodeCanonical(deviceAuthStructure);

        // Wrap in Tag24 for detached payload (Critical for OID4VP/ISO 18013-5)
        const deviceAuthTag24 = new cbor.Tagged(24, deviceAuthBytes);
        const deviceAuthTag24Bytes = cbor.encodeCanonical(deviceAuthTag24);

        // 7. Sign with Device Key (Askar)
        const deviceAuthProtectedMap = new Map();
        deviceAuthProtectedMap.set(1, -7); // alg: ES256
        const deviceAuthProtected = cbor.encodeCanonical(deviceAuthProtectedMap);

        const deviceSigStructure = [
            "Signature1",
            deviceAuthProtected,
            Buffer.alloc(0),
            deviceAuthTag24Bytes
        ];
        const deviceToBeSigned = cbor.encodeCanonical(deviceSigStructure);

        let deviceSignature = Buffer.from(deviceKey.signMessage({ message: deviceToBeSigned, sigType: SigAlgs.ES256 }));

        // Normalize S (Low S)
        // Reuse n and halfN from above

        const r = deviceSignature.subarray(0, 32);
        let s = deviceSignature.subarray(32, 64);

        // Compare s with halfN
        let sBig = BigInt("0x" + s.toString('hex'));

        if (sBig > halfNBig) {
            sBig = nBig - sBig;
            s = Buffer.from(sBig.toString(16).padStart(64, '0'), 'hex');
            deviceSignature = Buffer.concat([r, s]);
        }

        // 8. Verify with Askar (Credo)
        const isValidAskar = deviceKey.verifySignature({
            message: deviceToBeSigned,
            signature: deviceSignature,
            sigType: SigAlgs.ES256
        });
        expect(isValidAskar).toBe(true);

        // 9. Assemble DeviceResponse
        const deviceAuthCose = [
            deviceAuthProtected,
            new Map(),
            null, // detached payload
            deviceSignature
        ];

        const deviceSigned = {
            "nameSpaces": deviceNameSpacesTagged,
            "deviceAuth": {
                "deviceSignature": deviceAuthCose
            }
        };

        const issuerSignedItemTagged = new cbor.Tagged(24, cbor.encodeCanonical(item));
        const issuerSigned = {
            "nameSpaces": {
                "org.iso.18013.5.1": [ issuerSignedItemTagged ]
            },
            "issuerAuth": issuerAuth
        };

        const deviceResponse = {
            "version": "1.0",
            "documents": [
                {
                    "docType": "org.iso.18013.5.1.mDL",
                    "issuerSigned": issuerSigned,
                    "deviceSigned": deviceSigned
                }
            ],
            "status": 0
        };

        const deviceResponseBytes = cbor.encodeCanonical(deviceResponse);

        // Save artifacts for Python verification
        fs.writeFileSync(path.join(ARTIFACTS_DIR, 'credo_oid4vp_device_response.cbor'), deviceResponseBytes);
        fs.writeFileSync(path.join(ARTIFACTS_DIR, 'credo_oid4vp_session_transcript.cbor'), sessionTranscriptBytes);
        fs.writeFileSync(path.join(ARTIFACTS_DIR, 'credo_oid4vp_issuer_cert.pem'), rootCertPem);

        // Save params for Python test
        const params = {
            nonce,
            clientId,
            responseUri
        };
        fs.writeFileSync(path.join(ARTIFACTS_DIR, 'credo_oid4vp_params.json'), JSON.stringify(params));
    });
});

async function coseKeyFromAskarKey(key: Key): Promise<Map<number, any>> {
    const jwk = key.jwkPublic;
    if (!jwk.x || !jwk.y) {
        throw new Error("Invalid JWK from Askar key");
    }
    const x = Buffer.from(jwk.x, 'base64');
    const y = Buffer.from(jwk.y, 'base64');

    const coseKey = new Map();
    coseKey.set(1, 2); // kty: EC2
    coseKey.set(3, -7); // alg: ES256
    coseKey.set(-1, 1); // crv: P-256
    coseKey.set(-2, x); // x
    coseKey.set(-3, y); // y

    return coseKey;
}
