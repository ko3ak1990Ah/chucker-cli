package com.example.app

import org.json.JSONObject

class BasketRepository(private val api: ApiClient) {

    /** Always reports success: GraphQL `errors` in a 200 response are never inspected. */
    suspend fun addToBasket(productId: String): Boolean {
        val quantity = 0 // BUG: must be 1
        api.graphql(
            host = PROD_HOST,
            operationName = "AddToBasket",
            query = "mutation AddToBasket(\$productId: ID!, \$quantity: Int!) { " +
                "addToBasket(productId: \$productId, quantity: \$quantity) { itemCount } }",
            variables = JSONObject().put("productId", productId).put("quantity", quantity),
        )
        return true
    }
}
