package tech.indicio.isomdl_uniffi

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import uniffi.isomdl_uniffi.AuthenticationStatus
import uniffi.isomdl_uniffi.MdlPresentationSession
import uniffi.isomdl_uniffi.P256KeyPair
import uniffi.isomdl_uniffi.establishSession
import uniffi.isomdl_uniffi.generateTestMdl
import uniffi.isomdl_uniffi.handleResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class CommonGreetingTest {

    val utrechtCert = """-----BEGIN CERTIFICATE-----
MIICWTCCAf+gAwIBAgIULZgAnZswdEysOLq+G0uNW0svhYIwCgYIKoZIzj0EAwIw
VjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMREwDwYDVQQKDAhTcHJ1Y2VJRDEn
MCUGA1UEAwweU3BydWNlSUQgVGVzdCBDZXJ0aWZpY2F0ZSBSb290MB4XDTI1MDIx
MjEwMjU0MFoXDTI2MDIxMjEwMjU0MFowVjELMAkGA1UEBhMCVVMxCzAJBgNVBAgM
Ak5ZMREwDwYDVQQKDAhTcHJ1Y2VJRDEnMCUGA1UEAwweU3BydWNlSUQgVGVzdCBD
ZXJ0aWZpY2F0ZSBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwWfpUAMW
HkOzSctR8szsMNLeOCMyjk9HAkAYZ0HiHsBMNyrOcTxScBhEiHj+trE5d5fVq36o
cvrVkt2X0yy/N6OBqjCBpzAdBgNVHQ4EFgQU+TKkY3MApIowvNzakcIr6P4ZQDQw
EgYDVR0TAQH/BAgwBgEB/wIBADA+BgNVHR8ENzA1MDOgMaAvhi1odHRwczovL2lu
dGVyb3BldmVudC5zcHJ1Y2VpZC5jb20vaW50ZXJvcC5jcmwwDgYDVR0PAQH/BAQD
AgEGMCIGA1UdEgQbMBmBF2lzb2ludGVyb3BAc3BydWNlaWQuY29tMAoGCCqGSM49
BAMCA0gAMEUCIAJrzCSS/VIjf7uTq+Kt6+97VUNSvaAAwdP6fscIvp4RAiEA0dOP
Ld7ivuH83lLHDuNpb4NShfdBG57jNEIPNUs9OEg=
-----END CERTIFICATE-----"""

    @Test
    fun testExample() = runTest {
        uniffiStack {
            // Generate holder key
            val key = P256KeyPair().toStack()

            // Create test MDL
            val mdoc = generateTestMdl(key).toStack()


            val details = mdoc.details()

            println("MDL: ${mdoc.stringify()}")
            println("DETAILS: ${Json.encodeToString(details)}")

            val bleUUID = "24e1935e-2dcd-47ac-86bf-7d5785be660a"

            // Holder starts presentation session
            val presentationSession = MdlPresentationSession(mdoc, bleUUID).toStack()

            // Holder displays shares URL with verifier
            val qrCode = presentationSession.getQrCodeUri()
            println("QR: $qrCode")

            // Verifier establishes session
            val readerSessionData = establishSession(
                qrCode,
                mapOf(
                    "org.iso.18013.5.1" to mapOf(
                        "given_name" to true,
                        "family_name" to false
                    )
                ),
                listOf(utrechtCert)
            ).toStack()

            // Holder receives request
            val requestedData = presentationSession.handleRequest(readerSessionData.request)

            // Accept all requested data:
            val permittedItems = buildMap {
                requestedData.forEach { rd ->
                    put(rd.docType, buildMap {
                        rd.namespaces.forEach { (k, v) ->
                            put(k, buildList {
                                v.forEach { (k2, v2) ->
                                    if (v2) {
                                        add(k2)
                                    }
                                }
                            })
                        }
                    })
                }
            }

            // Holder generates unsigned response
            val unsignedResponse = presentationSession.generateResponse(permittedItems)

            // Holder signs response with key that matches mdoc public key
            val signedResponse = key.sign(unsignedResponse)

            // Holder submits response
            val response = presentationSession.submitResponse(signedResponse)

            // Verifier handles response
            val readerResult = handleResponse(readerSessionData.state, response).toStack()

            println(
                "Reader result: ${
                    mapOf(
                        "response" to readerResult.verifiedResponse,
                        "issuer_auth" to readerResult.issuerAuthentication,
                        "device_auth" to readerResult.deviceAuthentication,
                        "errors" to readerResult.errors
                    )
                }"
            )

            assertEquals(AuthenticationStatus.VALID, readerResult.issuerAuthentication)
            assertEquals(AuthenticationStatus.VALID, readerResult.deviceAuthentication)
            assertNull(readerResult.errors)
        }
    }
}