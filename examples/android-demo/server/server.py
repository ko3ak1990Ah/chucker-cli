#!/usr/bin/env python3
"""Mock GraphQL backend for the Demo Shop app. Serves api.example.com and api-tst.example.com."""

import json
import random
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Backend order: price ascending (ties by id). The app must show products in exactly this order.
PRODUCTS = [
    {"id": "p-1008", "name": "Cucumber", "price": {"amount": 0.79, "currency": "EUR"}},
    {"id": "p-1010", "name": "Chopped Tomatoes 400g", "price": {"amount": 0.89, "currency": "EUR"}},
    {"id": "p-1007", "name": "Bananas, loose (per kg)", "price": {"amount": 0.99, "currency": "EUR"}},
    {"id": "p-1014", "name": "Carrots 1kg", "price": {"amount": 1.09, "currency": "EUR"}},
    {"id": "p-1009", "name": "Spaghetti 500g", "price": {"amount": 1.15, "currency": "EUR"}},
    {"id": "p-1018", "name": "Penne 500g", "price": {"amount": 1.25, "currency": "EUR"}},
    {"id": "p-1002", "name": "Whole Milk 1L", "price": {"amount": 1.29, "currency": "EUR"}},
    {"id": "p-1011", "name": "Red Onions 1kg", "price": {"amount": 1.49, "currency": "EUR"}},
    {"id": "p-1024", "name": "Dark Chocolate 72% 100g", "price": {"amount": 1.79, "currency": "EUR"}},
    {"id": "p-1013", "name": "Lemons (4)", "price": {"amount": 1.89, "currency": "EUR"}},
    {"id": "p-1001", "name": "Organic Bananas", "price": {"amount": 1.99, "currency": "EUR"}},
    {"id": "p-1017", "name": "Hummus 200g", "price": {"amount": 1.99, "currency": "EUR"}},
    {"id": "p-1016", "name": "Orange Juice 1L", "price": {"amount": 2.29, "currency": "EUR"}},
    {"id": "p-1005", "name": "Greek Yoghurt 500g", "price": {"amount": 2.49, "currency": "EUR"}},
    {"id": "p-1015", "name": "Butter 250g", "price": {"amount": 2.69, "currency": "EUR"}},
    {"id": "p-1012", "name": "Basmati Rice 1kg", "price": {"amount": 2.79, "currency": "EUR"}},
    {"id": "p-1019", "name": "Peanut Butter 350g", "price": {"amount": 3.29, "currency": "EUR"}},
    {"id": "p-1003", "name": "Sourdough Bread", "price": {"amount": 3.49, "currency": "EUR"}},
    {"id": "p-1004", "name": "Free-range Eggs (10)", "price": {"amount": 3.89, "currency": "EUR"}},
    {"id": "p-1020", "name": "Ground Coffee 250g", "price": {"amount": 4.49, "currency": "EUR"}},
    {"id": "p-1006", "name": "Aged Gouda 250g", "price": {"amount": 4.79, "currency": "EUR"}},
    {"id": "p-1023", "name": "Salmon Fillets 250g", "price": {"amount": 5.49, "currency": "EUR"}},
    {"id": "p-1022", "name": "Chicken Breast 500g", "price": {"amount": 5.99, "currency": "EUR"}},
    {"id": "p-1021", "name": "Extra Virgin Olive Oil 500ml", "price": {"amount": 6.99, "currency": "EUR"}},
]

PROFILE = {
    "id": "user-4242",
    "firstName": "Jane",
    "lastName": "Doe",
    "email": "jane.doe@example.com",
    "phone": "+31 6 1234 5678",
}

basket_count = 0


def products(_variables):
    return {"data": {"products": PRODUCTS}}


def add_to_basket(variables):
    global basket_count
    quantity = variables.get("quantity")
    if not isinstance(quantity, int) or quantity < 1:
        return {
            "data": {"addToBasket": None},
            "errors": [
                {
                    "message": 'Variable "quantity" must be positive',
                    "path": ["addToBasket"],
                    "extensions": {"code": "BAD_USER_INPUT", "argument": "quantity", "received": quantity},
                }
            ],
        }
    basket_count += quantity
    return {"data": {"addToBasket": {"itemCount": basket_count}}}


def profile(_variables):
    return {"data": {"me": PROFILE}}


OPERATIONS = {"Products": products, "AddToBasket": add_to_basket, "Profile": profile}


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoGraphQL/1.0"
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        started = time.monotonic()
        host = self.headers.get("Host", "?")
        operation = "?"
        if self.path != "/graphql":
            status, payload = 404, {"errors": [{"message": "Not found"}]}
        else:
            try:
                length = int(self.headers.get("Content-Length", 0))
                request = json.loads(self.rfile.read(length) or b"{}")
                operation = request.get("operationName") or "?"
                handler = OPERATIONS.get(operation)
                if handler is None:
                    status, payload = 200, {"errors": [{"message": f'Unknown operation "{operation}"'}]}
                else:
                    status, payload = 200, handler(request.get("variables") or {})
            except (ValueError, json.JSONDecodeError):
                status, payload = 400, {"errors": [{"message": "Malformed JSON body"}]}

        time.sleep(random.uniform(0.05, 0.2))
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "sid=s3ss10n-7f2c9a41d8; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(body)

        outcome = "errors" if "errors" in payload else "ok"
        took = (time.monotonic() - started) * 1000
        print(f"{time.strftime('%H:%M:%S')} {host} {operation} -> {status} {outcome} ({took:.0f} ms)", flush=True)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    print("Mock GraphQL server on http://0.0.0.0:8080/graphql", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
