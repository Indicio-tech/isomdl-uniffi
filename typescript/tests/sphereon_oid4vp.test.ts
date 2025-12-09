
import * as fs from 'fs';
import * as path from 'path';
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
import { com } from '@sphereon/kmp-mdoc-core';

// Use Node's native WebCrypto
const webcrypto = crypto.webcrypto;

const ARTIFACTS_DIR = path.join(__dirname, '../../python/tests/cross_language_artifacts');

describe('Sphereon OID4VP Compatibility Tests', () => {
    
    beforeAll(() => {
        if (!fs.existsSync(ARTIFACTS_DIR)) {
            fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
        }
    });

    test('should generate a spec-compliant OID4VP DeviceResponse using Sphereon libraries', async () => {
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
        
        const dsCertDer = new Int8Array(dsCert.rawData);
        
        // 2. Generate Device Key
        const deviceKeyPair = await webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
        const deviceKeyJwk = await webcrypto.subtle.exportKey("jwk", deviceKeyPair.publicKey);
        
        // Manually build CoseKeyCbor from JWK
        const x = deviceKeyJwk.x ? Buffer.from(deviceKeyJwk.x, 'base64') : null;
        const y = deviceKeyJwk.y ? Buffer.from(deviceKeyJwk.y, 'base64') : null;
        
        const cbor = com.sphereon.cbor.CDDL;
        const kmp = com.sphereon.kmp;

        const coseKeyBuilder = com.sphereon.crypto.cose.CoseKeyCbor.Static.builder();
        coseKeyBuilder.withKty(com.sphereon.crypto.cose.CoseKeyType.EC2);
        coseKeyBuilder.withCrv(com.sphereon.crypto.cose.CoseCurve.P_256);
        coseKeyBuilder.withKid("device-key");
        if (x) coseKeyBuilder.withX(x.toString('hex'));
        if (y) coseKeyBuilder.withY(y.toString('hex'));
        
        const deviceKeyCbor = coseKeyBuilder.build();
        
        // Wrap in DeviceKeyInfoCbor
        const deviceKeyInfoCbor = new com.sphereon.mdoc.data.mso.DeviceKeyInfoCbor(
            deviceKeyCbor,
            null, null
        );

        // Debug n2l error - Removed


        // 3. Create Data Elements using MsoBuilder
        const createItem = (id: number, key: string, value: any) => {
            const digestId = cbor.uint.newUint(com.sphereon.kmp.LongKMP.fromNumber(id));
            const randomBytes = new Int8Array(crypto.randomBytes(16));
            const random = cbor.bstr.newByteString(randomBytes);
            const elementId = cbor.tstr.newString(key);
            const elementVal = cbor.tstr.newString(value); 
            
            return new com.sphereon.mdoc.data.device.IssuerSignedItemCbor(
                digestId,
                random,
                elementId,
                elementVal
            );
        };
        
        const items = [
            createItem(0, "family_name", "Doe"),
            createItem(1, "given_name", "John")
        ];
        
        const nameSpace = "org.iso.18013.5.1";
        const nsString = cbor.tstr.newString(nameSpace);
        
        // Manual construction of namespaces map
        const encodedItems = items.map(item => {
             const bytes = item.cborEncode();
             const byteString = cbor.bstr.newByteString(bytes);
             return new com.sphereon.cbor.CborEncodedItem(item, byteString);
        });
        
        const encodedItemsList = kmp.kmpListOf(encodedItems);
        const cborArray = new com.sphereon.cbor.CborArray(encodedItemsList as any);
        
        const nsMap = kmp.kmpMapOf();
        nsMap.asJsMapView().set(nsString, cborArray);
        const cborNsMap = new com.sphereon.cbor.CborMap(nsMap as any);
        
        let msoBuilder = new com.sphereon.mdoc.data.device.IssuerSignedCbor.MsoBuilder(
            cbor.tstr.newString("org.iso.18013.5.1.mDL"),
            cborNsMap as any
        );
        
        // Set validity info
        const now = com.sphereon.kmp.LocalDateTimeKMP.Static.fromString("2024-01-01T00:00:00");
        const validUntil = com.sphereon.kmp.LocalDateTimeKMP.Static.fromString("2025-01-01T00:00:00");
        msoBuilder = msoBuilder.withValidityInfo(now, now, validUntil);
        
        // Set device key info
        msoBuilder = msoBuilder.withDeviceKey(deviceKeyCbor);
        
        // Build MSO and Namespaces
        const digestAlg = com.sphereon.crypto.generic.DigestAlg.SHA256;
        const buildResult = msoBuilder.build(digestAlg);
        
        // Handle Kotlin Pair in JS (mangled names or missing first/second properties)
        let mso = (buildResult as any).first;
        let nameSpacesMap = (buildResult as any).second;
        
        if (!mso) {
            // Fallback: assume the first property is the MSO and the second is the Map
            // Based on logs: ng_1 is MSO, og_1 is Map
            const values = Object.values(buildResult);
            mso = values[0];
            nameSpacesMap = values[1];
        }

        // 4. Sign MSO (Issuer Auth)
        const protectedHeader = new com.sphereon.crypto.cose.CoseHeaderCbor(
            com.sphereon.crypto.cose.CoseAlgorithm.ES256,
            null, null, null, null, null, null
        );
        
        // Create Unprotected Header with x5chain
        const x5chain = new com.sphereon.cbor.CborArray(kmp.kmpListOf([
            cbor.bstr.newByteString(dsCertDer)
        ]) as any);
        
        const unprotectedHeaderMap = kmp.kmpMapOf();
        unprotectedHeaderMap.asJsMapView().set(
            com.sphereon.crypto.cose.CoseHeaderCbor.Static.X5CHAIN,
            x5chain
        );
        const unprotectedHeader = new com.sphereon.cbor.CborMap(unprotectedHeaderMap as any);
        
        // Create Payload (Encoded MSO)
        const msoBytes = mso.cborEncode();
        const payload = cbor.bstr.newByteString(msoBytes);
        
        // Create Signature Structure
        // Sig_structure = [
        //   context: "Signature1",
        //   body_protected: empty_or_serialized_map,
        //   external_aad: bstr,
        //   payload: bstr
        // ]
        const protectedHeaderBytes = protectedHeader.cborEncode();
        
        // We need to construct the Sig_structure manually or use a helper if available.
        // CoseSignatureStructureCbor is available.
        const sigStructure = new com.sphereon.crypto.cose.CoseSignatureStructureCbor(
            com.sphereon.crypto.cose.SigStructure.Signature1.toCbor(),
            cbor.bstr.newByteString(protectedHeaderBytes),
            null, // signProtected
            cbor.bstr.newByteString(new Int8Array(0)), // external_aad
            payload
        );
        
        const toBeSigned = sigStructure.cborEncode();
        
        // Sign
        const signature = await webcrypto.subtle.sign(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            rootKeyPair.privateKey,
            new Uint8Array(toBeSigned)
        );
        
        console.log("CoseSign1Cbor.Static keys:", Object.keys(com.sphereon.crypto.cose.CoseSign1Cbor.Static));
        
        const issuerAuth = new com.sphereon.crypto.cose.CoseSign1Cbor(
            protectedHeader,
            unprotectedHeader as any, // unprotected header
            payload,
            cbor.bstr.newByteString(new Int8Array(signature))
        );

        // 5. Construct IssuerSigned
        const issuerSigned = new com.sphereon.mdoc.data.device.IssuerSignedCbor(
            nameSpacesMap,
            issuerAuth
        );

        // 5.5 Construct DeviceSigned
        const clientId = "client-id";
        const responseUri = "https://response-uri";
        const nonce = "nonce-123";
        
        const clientIdHash = crypto.createHash('sha256').update(clientId).digest();
        const responseUriHash = crypto.createHash('sha256').update(responseUri).digest();
        
        const oid4vpHandover = new com.sphereon.cbor.CborArray(kmp.kmpListOf([
            cbor.bstr.newByteString(new Int8Array(clientIdHash)),
            cbor.bstr.newByteString(new Int8Array(responseUriHash)),
            cbor.tstr.newString(nonce)
        ]) as any);
        
        const sessionTranscript = new com.sphereon.cbor.CborArray(kmp.kmpListOf([
            new com.sphereon.cbor.CborNull(),
            new com.sphereon.cbor.CborNull(),
            oid4vpHandover
        ]) as any);
        
        const sessionTranscriptBytes = sessionTranscript.cborEncode();
        
        // Device Authentication
        const deviceNameSpaces = new com.sphereon.cbor.CborMap(kmp.kmpMapOf() as any);
        const deviceNameSpacesBytes = deviceNameSpaces.cborEncode();
        
        // Protected Header for Device Auth
        const deviceProtectedHeader = new com.sphereon.crypto.cose.CoseHeaderCbor(
            com.sphereon.crypto.cose.CoseAlgorithm.ES256,
            null, null, null, null, null, null
        );
        const deviceProtectedHeaderBytes = deviceProtectedHeader.cborEncode();
        
        const deviceSigStructure = new com.sphereon.crypto.cose.CoseSignatureStructureCbor(
            com.sphereon.crypto.cose.SigStructure.Signature1.toCbor(),
            cbor.bstr.newByteString(deviceProtectedHeaderBytes),
            null,
            cbor.bstr.newByteString(sessionTranscriptBytes), // external_aad = SessionTranscript
            cbor.bstr.newByteString(deviceNameSpacesBytes)   // payload = DeviceNameSpacesBytes
        );
        
        const deviceToBeSigned = deviceSigStructure.cborEncode();
        
        const deviceSignature = await webcrypto.subtle.sign(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            deviceKeyPair.privateKey,
            new Uint8Array(deviceToBeSigned)
        );
        
        const deviceAuth = new com.sphereon.crypto.cose.CoseSign1Cbor(
            deviceProtectedHeader,
            null,
            null, // Detached payload
            cbor.bstr.newByteString(new Int8Array(deviceSignature))
        );
        
        const deviceAuthWrapper = new com.sphereon.mdoc.data.device.DeviceAuthCbor(
            deviceAuth,
            null
        );
        
        const deviceSigned = new com.sphereon.mdoc.data.device.DeviceSignedCbor(
            deviceNameSpaces as any,
            deviceAuthWrapper
        );

        // 6. Construct Document
        const docTypeString = cbor.tstr.newString("org.iso.18013.5.1.mDL");
        const document = new com.sphereon.mdoc.data.device.DocumentCbor(
            docTypeString,
            issuerSigned,
            deviceSigned
        );

        // 7. Construct DeviceResponse
        const documents = [document];
        const deviceResponse = new com.sphereon.mdoc.data.device.DeviceResponseCbor(
            cbor.tstr.newString("1.0"),
            documents,
            null,
            cbor.uint.newUint(com.sphereon.kmp.LongKMP.fromNumber(0)) // Status OK
        );

        const encodedDeviceResponse = deviceResponse.cborEncode();
        expect(encodedDeviceResponse).toBeDefined();
        expect(encodedDeviceResponse.length).toBeGreaterThan(0);

        // Save to file
        fs.writeFileSync(path.join(ARTIFACTS_DIR, 'sphereon_oid4vp_device_response.cbor'), new Uint8Array(encodedDeviceResponse));
        fs.writeFileSync(path.join(ARTIFACTS_DIR, 'sphereon_oid4vp_issuer_cert.pem'), rootCert.toString("pem"));
        fs.writeFileSync(path.join(ARTIFACTS_DIR, 'sphereon_oid4vp_params.json'), JSON.stringify({
            nonce,
            clientId,
            responseUri
        }));
    });
});
