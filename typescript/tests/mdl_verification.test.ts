
import * as fs from 'fs';
import * as path from 'path';
import * as cbor from 'cbor';
import { Key, SigAlgs, KeyAlgs } from '@hyperledger/aries-askar-nodejs';
import * as crypto from 'crypto';

// Define paths
const ARTIFACTS_DIR = path.join(__dirname, '../../python/tests/cross_language_artifacts');
const MDL_PATH = path.join(ARTIFACTS_DIR, 'mdl.txt');

describe('Cross-Language mDL Verification', () => {
  let mdlBytes: Buffer;

  beforeAll(() => {
    // Read artifacts
    const mdlBase64 = fs.readFileSync(MDL_PATH, 'utf8').trim();
    mdlBytes = Buffer.from(mdlBase64, 'base64');
  });

  test('should parse mDL as valid CBOR', async () => {
    const decoded = await cbor.decodeFirst(mdlBytes);
    expect(decoded).toBeDefined();
  });

  test('should verify issuer signature using Credo/Askar', async () => {
    // 1. Parse mDL to find IssuerAuth (COSE_Sign1)
    const decoded = await cbor.decodeFirst(mdlBytes);
    
    expect(decoded.issuer_auth).toBeDefined();
    
    const issuerAuth = decoded.issuer_auth; // This should be the COSE_Sign1
    
    // COSE_Sign1 is an array: [protected, unprotected, payload, signature]
    expect(Array.isArray(issuerAuth)).toBe(true);
    expect(issuerAuth.length).toBe(4);
    
    const [protectedHeaders, unprotectedHeaders, payload, signature] = issuerAuth;
    
    let payloadBytes = payload;
    if (!payloadBytes || payloadBytes.length === 0) {
        if (decoded.mso) {
             payloadBytes = decoded.mso;
        }
    }

    // 2. Verify Signature
    // We need to construct the Sig_structure for COSE verification
    // Sig_structure = [
    //   "Signature1",
    //   protectedHeaders,
    //   external_aad,
    //   payload
    // ]
    
    const sigStructure = [
      "Signature1",
      protectedHeaders,
      Buffer.alloc(0), // external_aad is empty for mDL
      payloadBytes
    ];
    
    const toBeSigned = cbor.encodeCanonical(sigStructure);

    // Extract x5chain from unprotected headers
    const x5chain = unprotectedHeaders.get(33);
    if (!x5chain || !Array.isArray(x5chain) || x5chain.length === 0) {
        throw new Error('x5chain not found in unprotected headers');
    }
    
    const leafCert = x5chain[0];
    
    // Create public key from certificate
    // Convert to PEM
    const pem = '-----BEGIN CERTIFICATE-----\n' + leafCert.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----';
    const issuerPublicKey = crypto.createPublicKey(pem);
    
    // Export as JWK to use with Askar
    const issuerKeyJwkFromCert = issuerPublicKey.export({ format: 'jwk' });
    
    // Import Key using Askar via public bytes (JWK import seems flaky)
    const x = Buffer.from(issuerKeyJwkFromCert.x!, 'base64url');
    const y = Buffer.from(issuerKeyJwkFromCert.y!, 'base64url');
    const uncompressedKey = Buffer.concat([Buffer.from([0x04]), x, y]);
    
    const key = Key.fromPublicBytes({ 
        algorithm: KeyAlgs.EcSecp256r1, 
        publicKey: uncompressedKey 
    });
    
    // Verify using Askar
    const verified = key.verifySignature({ 
        message: toBeSigned, 
        signature: signature,
        sigType: SigAlgs.ES256 
    });
    
    expect(verified).toBe(true);
  });
});
