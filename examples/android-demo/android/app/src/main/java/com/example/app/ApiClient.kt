package com.example.app

import android.content.Context
import android.util.Base64
import com.chuckerteam.chucker.api.ChuckerCollector
import com.chuckerteam.chucker.api.ChuckerInterceptor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.net.InetAddress

const val PROD_HOST = "api.example.com"
const val TEST_HOST = "api-tst.example.com"

/** Both demo hosts resolve to the host machine, where `server/server.py` listens. */
private object EmulatorHostDns : Dns {
    private val hostMachine = InetAddress.getByName("10.0.2.2")

    override fun lookup(hostname: String): List<InetAddress> =
        if (hostname == PROD_HOST || hostname == TEST_HOST) listOf(hostMachine) else Dns.SYSTEM.lookup(hostname)
}

private object FakeCredentials {
    private fun b64(json: String): String =
        Base64.encodeToString(json.toByteArray(), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    val jwt: String = listOf(
        b64("""{"alg":"HS256","typ":"JWT"}"""),
        b64("""{"sub":"user-4242","name":"Jane Doe","scope":"shop","iat":1767225600}"""),
        b64("demo-signature-not-a-real-key"),
    ).joinToString(".")

    const val SESSION_ID = "s3ss10n-7f2c9a41d8"
    const val DEVICE_ID = "5b1e7c2a-9d34-4f6b-a8e0-3c71d2f90b55"
}

class ApiClient(context: Context) {

    private val client = OkHttpClient.Builder()
        .dns(EmulatorHostDns)
        .addInterceptor { chain ->
            chain.proceed(
                chain.request().newBuilder()
                    .header("Authorization", "Bearer ${FakeCredentials.jwt}")
                    .header("Cookie", "sid=${FakeCredentials.SESSION_ID}")
                    .header("X-Device-Id", FakeCredentials.DEVICE_ID)
                    .build()
            )
        }
        .addInterceptor(
            ChuckerInterceptor.Builder(context)
                .collector(ChuckerCollector(context, showNotification = false))
                .build()
        )
        .build()

    suspend fun graphql(
        host: String,
        operationName: String,
        query: String,
        variables: JSONObject = JSONObject(),
    ): JSONObject = withContext(Dispatchers.IO) {
        val payload = JSONObject()
            .put("operationName", operationName)
            .put("query", query)
            .put("variables", variables)
        val request = Request.Builder()
            .url("http://$host:8080/graphql")
            // Chucker fills its GraphQL operation column from this header only.
            .header("X-APOLLO-OPERATION-NAME", operationName)
            .post(payload.toString().toRequestBody("application/json".toMediaType()))
            .build()
        client.newCall(request).execute().use { response ->
            JSONObject(response.body.string())
        }
    }
}
