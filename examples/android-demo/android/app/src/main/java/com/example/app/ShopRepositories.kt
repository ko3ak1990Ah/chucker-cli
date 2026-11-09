package com.example.app

import org.json.JSONObject

data class Product(val id: String, val name: String, val price: String)

data class Profile(val name: String, val email: String, val phone: String)

class ProductRepository(private val api: ApiClient) {
    suspend fun products(): List<Product> {
        val data = api.graphql(
            host = PROD_HOST,
            operationName = "Products",
            query = "query Products { products { id name price { amount currency } } }",
        ).getJSONObject("data")
        val items = data.getJSONArray("products")
        val products = (0 until items.length()).map { i ->
            val item = items.getJSONObject(i)
            val price = item.getJSONObject("price")
            Product(
                id = item.getString("id"),
                name = item.getString("name"),
                price = "€ %.2f".format(price.getDouble("amount")),
            )
        }
        return products.sortedBy { it.name } // BUG: must keep backend order
    }
}

class ProfileRepository(private val api: ApiClient) {
    suspend fun profile(): Profile {
        val me = api.graphql(
            host = TEST_HOST,
            operationName = "Profile",
            query = "query Profile { me { id firstName lastName email phone } }",
        ).getJSONObject("data").getJSONObject("me")
        return Profile(
            name = "${me.getString("firstName")} ${me.getString("lastName")}",
            email = me.getString("email"),
            phone = me.getString("phone"),
        )
    }
}
