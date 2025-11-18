package tech.indicio.isomdl_uniffi

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import uniffi.isomdl_uniffi.AuthenticationStatus
import uniffi.isomdl_uniffi.MdlPresentationSession
import uniffi.isomdl_uniffi.Mdoc
import uniffi.isomdl_uniffi.P256KeyPair
import uniffi.isomdl_uniffi.establishSession
import uniffi.isomdl_uniffi.generateTestMdl
import uniffi.isomdl_uniffi.handleResponse
import uniffi.isomdl_uniffi.iso1801351AamvaFromJson
import uniffi.isomdl_uniffi.iso1801351FromJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class CommonGreetingTest {
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

    @Test
    fun generateMdl() = runTest{
        val holderKey = P256KeyPair();

        val mdoc = Mdoc.createAndSign(
            "org.iso.18013.5.1.mDL",
            buildMap{
                put("org.iso.18013.5.1", iso1801351FromJson(sampleMdlData))
                put("org.iso.18013.5.1.aamva", iso1801351AamvaFromJson(sampleAamvaData))
            },
            holderKey.publicJwk(),
            utrechtCert,
            utrechtKey
        )

        println("Mdoc: ${mdoc.stringify()}")
    }

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

    val utrechtKey = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMIAu+2XfU/9Cwv3H
oI5nExdS8cA9Js/kzoXmMueGYJuhRANCAATBZ+lQAxYeQ7NJy1HyzOww0t44IzKO
T0cCQBhnQeIewEw3Ks5xPFJwGESIeP62sTl3l9Wrfqhy+tWS3ZfTLL83
-----END PRIVATE KEY-----"""

    val sampleMdlData = """
         {
          "family_name":"Smith",
          "given_name":"Alice",
          "birth_date":"1980-01-01",
          "issue_date":"2020-01-01",
          "expiry_date":"2030-01-01",
          "issuing_country":"US",
          "issuing_authority":"NY DMV",
          "document_number":"DL12345678",
          "portrait": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/2wBDAQMDAwQDBAgEBAgQCwkLEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/wAARCAA8AEsDAREAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD9U6ACgAoAyfE3inQvB+nQ6t4jvvslpcahYaXHJ5Tybrq9uorS2jwgJG+eeJM42ruyxCgkAGtQBk6z4p0Lw/qOhaTq999nu/E2oPpelx+U7/aLpLW4u2jyoITEFpcPliF+TGdzKCAa1ABQAUAFABQAUAeFftR/G/wD8KtF0ybU/i94f8L+I9G1jRdebT7nX4bW7uNEGoJFqbCyaQNeobD+0AkQjkZpUUwqbiOIqAZWuar8efjHffDj4heCvgdaeG9N8Law3iJbD4geJP7I1W7M2kX1mIzbWNtfrboF1FXzNIsweGSN4E+WQgHVR/Fb42+HNVuLf4j/ALOF2+kRW8NyNa8D+I4NeghQtILgTW1zHZXzPEiRuEtba5eQSbUBkGxgA/Z41bSvi34Zsf2jptTtNXvPGFvcHRXhmWWLRtEe4Jh09FUlYbnbFCb4BnZruJ0MjRW1tHCAewUAFABQAUAFAHFfGjxrqvw++F/iDxP4ct7S58QrbrY+HbS7RmgvNbupFttNtpNrLtSW8mt4ixdFUOWZ0UFwAHwh+EPg34JeDY/BngyC7dHuJdQ1PU9QnNzqOsajMQ1xf3tw3zT3MrDLOfRVUKiqqgHVaZHqsVs66ze2l1cG4nZHtrZoEEBlcwoVaRyXWIxo77gHdWcLGGEagBqceqy2yLo17aWtwLiBne5tmnQwCVDMgVZEIdohIiPuIR2VysgUxsAeP+NrWz+A/jbQviF4N8LeT4b8Z+IINA8ZabpEcFvG2papeQw2WvSIzKrzLdSC2nMa+dNHfJJI0gsokoA9roAKACgAoAKAPKv2lv8AknWkf9lA8Cf+pVpdAHqtAHPx+P8AwbL4/uPhaviG0Hiy10eHX30liVnOnSzSQLcICMOglhdG2k7CY9+3zI9wBaufFOhWnirTvBVxfbNa1XT73VLO28pz5traSW0dxJvA2Lte9thgkMfMyoIViADlf2gfhn/wuT4HePPhbHaaVcXfibw/fafYf2pHvtYb54W+yzv8jlfKnEUgdVLIyBlG5RQB0Hw98a6V8SvAHhr4jaFb3cGm+KtHstbs4rtFWeOC5hSaNZFVmUOFcAgMwznBPWgDoKACgAoAKAMnxZ4W0Lxz4V1nwV4psftui+INPuNL1G2814/PtZ42jlj3oVddyOwypDDOQQeaAOA8J/EjXfBn9jfD342Weqxa0Ps+kweMfsKHRvEd0dsaz+Zb5TTppnaEfZ7pYFNxceRatdhRIwB0HxG+HNz40udD8Q+HvFV34Y8T+GLia50zU7a2inSVJYikljeRuN09jKwheWBJInZ7aB0likijkUA5/wAHfCv4jxfFNPit8VPihpXiG703w/ceHtG0vQvDR0extI7q5gnvJ5fOurqaaaQ2dmq/vUjRYWwhaQsACp+1nJqt/wDAbxP4B8NWVpfeIfiLb/8ACD6PaXFy0IafU820k/yRyOyW1vJcXkoRGIhtJmO1VZ1APYKACgAoAKACgAoAqatpOla/pV7oWu6Zaajpuo28lpeWd3Cs0FzBIpWSKSNgVdGUlSpBBBINAHmv/CmPFXhX9/8ACb40+K9I2fONL8U3EnirS55m+V5JmvZP7S+5jbHBqEESuiPsbMqygB/wjn7U/wD0WT4Vf+G01H/5e0Aavhb4aa6uu2vjT4o+N/8AhLtesN7abBb6amn6Po8jo0Uk1labpZRNJCdjS3FxcSKHuFhaCKeWJgD0CgAoAKACgAoAKACgAoAKACgAoAKACgAoAKACgAoAKACgAoAKACgAoAKAP//Z",
          "driving_privileges":[
            {
               "vehicle_category_code":"A",
               "issue_date":"2020-01-01",
               "expiry_date":"2030-01-01"
            },
            {
               "vehicle_category_code":"B",
               "issue_date":"2020-01-01",
               "expiry_date":"2030-01-01"
            }
          ],
          "un_distinguishing_sign":"USA",
          "administrative_number":"ABC123",
          "sex":1,
          "height":170,
          "weight":70,
          "eye_colour":"hazel",
          "hair_colour":"red",
          "birth_place":"Canada",
          "resident_address":"138 Eagle Street",
          "portrait_capture_date":"2020-01-01T12:00:00Z",
          "age_in_years":43,
          "age_birth_year":1980,
          "age_over_18":true,
          "age_over_21":true,
          "issuing_jurisdiction":"US-NY",
          "nationality":"US",
          "resident_city":"Albany",
          "resident_state":"New York",
          "resident_postal_code":"12202-1719",
          "resident_country": "US"
        }
    """.trimIndent()

    val sampleAamvaData = """
        {
          "domestic_driving_privileges":[
            {
              "domestic_vehicle_class":{
                "domestic_vehicle_class_code":"A",
                "domestic_vehicle_class_description":"unknown",
                "issue_date":"2020-01-01",
                "expiry_date":"2030-01-01"
              }
            },
            {
              "domestic_vehicle_class":{
                "domestic_vehicle_class_code":"B",
                "domestic_vehicle_class_description":"unknown",
                "issue_date":"2020-01-01",
                "expiry_date":"2030-01-01"
              }
            }
          ],
          "name_suffix":"1ST",
          "organ_donor":1,
          "veteran":1,
          "family_name_truncation":"N",
          "given_name_truncation":"N",
          "aka_family_name.v2":"Smithy",
          "aka_given_name.v2":"Ally",
          "aka_suffix":"I",
          "weight_range":3,
          "race_ethnicity":"AI",
          "EDL_credential":1,
          "sex":1,
          "DHS_compliance":"F",
          "resident_county":"001",
          "hazmat_endorsement_expiration_date":"2024-01-30",
          "CDL_indicator":1,
          "DHS_compliance_text":"Compliant",
          "DHS_temporary_lawful_status":1
        }
    """.trimIndent()
}
