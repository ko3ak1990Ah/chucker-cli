import base64
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shlex
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "src" / "chucker_cli" / "cli.py"
spec = importlib.util.spec_from_file_location("chucker", SCRIPT)
chucker = importlib.util.module_from_spec(spec)
sys.modules["chucker"] = chucker
spec.loader.exec_module(chucker)

# Copied verbatim from Chucker 4.3.1's generated ChuckerDatabase_Impl.
CREATE_TABLE = (
    "CREATE TABLE IF NOT EXISTS `transactions` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `requestDate` INTEGER, "
    "`responseDate` INTEGER, `tookMs` INTEGER, `protocol` TEXT, `method` TEXT, `url` TEXT, `host` TEXT, `path` TEXT, "
    "`scheme` TEXT, `responseTlsVersion` TEXT, `responseCipherSuite` TEXT, `requestPayloadSize` INTEGER, "
    "`requestContentType` TEXT, `requestHeaders` TEXT, `requestHeadersSize` INTEGER, `requestBody` TEXT, "
    "`isRequestBodyEncoded` INTEGER NOT NULL, `responseCode` INTEGER, `responseMessage` TEXT, `error` TEXT, "
    "`responsePayloadSize` INTEGER, `responseContentType` TEXT, `responseHeaders` TEXT, `responseHeadersSize` INTEGER, "
    "`responseBody` TEXT, `isResponseBodyEncoded` INTEGER NOT NULL, `responseImageData` BLOB, "
    "`graphQlDetected` INTEGER NOT NULL, `graphQlOperationName` TEXT)"
)


def b64(raw: bytes, urlsafe: bool = False) -> str:
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=") if urlsafe else base64.b64encode(raw)
    return encoded.decode()


# Credential-shaped fixtures are assembled at runtime so secret scanners don't flag the test source.
JWT = ".".join(b64(part, urlsafe=True) for part in (b'{"alg":"HS256"}', b'{"sub":"12345"}', b"fixture-signature"))
BASIC_CREDENTIAL = b64(b"fixture-user:fixture-pass")
OPAQUE_BEARER = "opaquebearer444"
RAW_HOST_TOKEN = "allowlisted-token-abc"
SECRETS = (JWT, BASIC_CREDENTIAL, "fake-install-id-0000", "sid=SESSIONSECRET", "querysecret123", "jan@example.nl", "hunter2", "0612345678",
           "Jansen", "oauthcode999", "referertoken555", "opaque-apikey-777", "opaque-session-888", OPAQUE_BEARER,
           "fragtoken999", "jsonurl888", "truncsecret777", "decodedsfx987", "gqlpass321", "xmlpass246", "multipass135",
           "gqlblock432", "embedurl741", "decodedempty852", "formpass963", "739241", "formpin468",
           "userinfo852", "keyowner@example.test", "keytok951", "gqltrunc159", "gqlblocktrunc357", "gqlesc753",
           "gqllist111", "gqllist222", "nestedtok333",
           "nestedpw444", "nl555", "nl666", "pkceform258", "pkcejson369", "userpw147", "fragcap741")
NOW_MS = int(time.time() * 1000)


def headers(**pairs):
    return json.dumps([{"name": name.replace("_", "-"), "value": value} for name, value in pairs.items()])


def build_fixture(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute(CREATE_TABLE)
    rows = [
        dict(id=1, requestDate=NOW_MS - 3_600_000, tookMs=120, method="GET", host="api.example.com",
             path="/mobile-services/v1/basket?page=1&token=querysecret123&decodedsfx987",
             url="https://api.example.com/mobile-services/v1/basket?page=1&token=querysecret123&decodedsfx987",
             requestHeaders=headers(Authorization=f"Bearer {JWT}", Cookie="sid=SESSIONSECRET", Accept="application/json",
                                    X_Fraud_Detection_Installation_Id="fake-install-id-0000"),
             requestContentType="Application/X-Www-Form-Urlencoded", requestBody="user=x&password=formpass963&pin=formpin468&code_verifier=pkceform258",
             responseCode=200, responseMessage="OK", responseContentType="application/json",
             responseHeaders=headers(Content_Type="application/json", Set_Cookie="sid=SESSIONSECRET",
                                     Location="https://api.example.com/callback?code=oauthcode999&state=ok",
                                     Content_Location="https://api.example.com/cb#access_token=fragtoken999&x=1"),
             responseBody=json.dumps({"items": [{"name": "Melk", "price": 1.25}],
                                      "apiKey": "opaque-apikey-777", "sessionId": "opaque-session-888",
                                      "codeVerifier": "pkcejson369",
                                      "redirectUrl": "https://api.example.com/callback?token=jsonurl888&page=2",
                                      "customer": {"email": "jan@example.nl", "lastName": "Jansen",
                                                   "phone": "0612345678"},
                                      "note": "contact jan@example.nl",
                                      "message": "failed at https://api.example.com/cb?token=embedurl741 retry",
                                      "download": "https://alice:userinfo852!@files.example.com/r?download=1",
                                      "byOwner": {"keyowner@example.test": {"token": "keytok951"}},
                                      "logLine": f"Authorization: Basic {BASIC_CREDENTIAL}"})),
        dict(id=2, requestDate=NOW_MS - 120_000, tookMs=900, method="POST", host="api.example.com", path="/graphql?q=green beans&url=https://login.example/cb?token=nestedtok333",
             url="https://api.example.com/graphql?q=green beans&url=https://login.example/cb?token=nestedtok333", requestContentType="application/json",
             requestHeaders=headers(Authorization=f"Bearer {JWT}", Content_Length="42", Content_Encoding="gzip",
                                    Referer="https://www.example.com/page?token=referertoken555&tab=1"),
             requestBody=json.dumps({"query": 'mutation Login { login(user: "x", password: "gqlpass321", '
                                              'sessionToken: """gqlblock432""", pin: 739241) { ok } }',
                                     "variables": {"password": "hunter2"},
                                     "truncated": 'retry { login(password: "gqltrunc159',
                                     "truncatedBlock": 'retry { login(pin: """gqlblocktrunc357',
                                     "truncatedEscape": 'retry { login(secret: "gqlesc753\\',
                                     "batch": 'exchange(tokens: ["gqllist111", "gqllist222"])',
                                     "nested": 'login(input: {password: "nestedpw444"}, tokens: [["nl555"], ["nl666"]], keep: "visible")'}),
             responseCode=500, responseMessage="Server Error for jan@example.nl",
             responseContentType="application/json",
             responseBody=json.dumps({"errors": [{"message": "boom " + "x" * 200}]}),
             graphQlDetected=1, graphQlOperationName="FetchProduct"),
        dict(id=3, requestDate=NOW_MS - 60_000, method="GET", host="www.example.com", path="/\x1b[31mred",
             url="https://name@example.com:userpw147!sfx@www.example.com/red?page=1#access_token=fragcap741",
             error=f"java.net.UnknownHostException: www.example.com (Authorization: Bearer {OPAQUE_BEARER})",
             responseContentType="application/json", responseBody='{"accessToken":"truncsecret777",',
             requestContentType="application/xml", requestBody="<login><password>xmlpass246</password></login>"),
        dict(id=4, requestDate=NOW_MS - 30_000, tookMs=40, method="GET", host="static.example.com",
             path="/logo.png?password=&decodedempty852", url="https://static.example.com/logo.png?password=&decodedempty852", responseCode=200, responseContentType="image/png",
             requestContentType="multipart/form-data; boundary=b",
             requestBody='--b\r\nContent-Disposition: form-data; name="password"\r\n\r\nmultipass135\r\n--b--',
             responseBody="\x89PNG...", isResponseBodyEncoded=1, responseImageData=b"\x89PNG\r\n\x1a\n" * 10),
    ]
    for row in rows:
        row.setdefault("isRequestBodyEncoded", 0)
        row.setdefault("isResponseBodyEncoded", 0)
        row.setdefault("graphQlDetected", 0)
        columns = ", ".join(row)
        conn.execute(f"INSERT INTO transactions ({columns}) VALUES ({', '.join('?' * len(row))})", list(row.values()))
    conn.commit()
    conn.close()


class ChuckerCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = self.dir / "fixture.db"
        build_fixture(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *argv, snapshot=True):
        args = [*argv, "--snapshot", str(self.db)] if snapshot else list(argv)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = chucker.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def run_json(self, *argv, expected_exit=0, snapshot=True):
        code, out, err = self.run_cli(*argv, snapshot=snapshot)
        self.assertEqual(code, expected_exit, out + err)
        return json.loads(out)

    def assert_no_secrets(self, text):
        for secret in SECRETS:
            self.assertNotIn(secret, text)

    # ls / filters

    def test_ls_returns_newest_first_in_envelope(self):
        envelope = self.run_json("ls")
        self.assertTrue(envelope["ok"])
        self.assertEqual([row["id"] for row in envelope["data"]], [4, 3, 2, 1])
        self.assertEqual(envelope["meta"]["total"], 4)
        self.assertFalse(envelope["meta"]["has_more"])

    def test_ls_filters(self):
        ids = lambda *argv: [row["id"] for row in self.run_json("ls", *argv)["data"]]  # noqa: E731
        self.assertEqual(ids("--code", "5xx"), [2])
        self.assertEqual(ids("--code", "200,5xx"), [4, 2, 1])
        self.assertEqual(ids("--errors"), [3, 2])
        self.assertEqual(ids("--gql", "fetch"), [2])
        self.assertEqual(ids("--host", "static"), [4])
        self.assertEqual(ids("--method", "post"), [2])
        self.assertEqual(ids("--since", "10m"), [4, 3, 2])
        self.assertEqual(ids("--body-contains", "Melk"), [1])
        self.assertEqual(ids("--path", "100%_"), [])

    def test_ls_paging_and_fields(self):
        envelope = self.run_json("ls", "--limit", "1", "--offset", "1", "--fields", "id,status")
        self.assertEqual(envelope["data"], [{"id": 3, "status": None}])
        self.assertTrue(envelope["meta"]["has_more"])

    def test_summary_redacts_query_secret_and_marks_states(self):
        rows = {row["id"]: row for row in self.run_json("ls")["data"]}
        self.assertNotIn("querysecret123", rows[1]["path"])
        self.assertIn("page=1", rows[1]["path"])
        self.assertEqual(rows[3]["state"], "failed")
        self.assertEqual(rows[2]["graphql"], "FetchProduct")
        self.assertEqual(rows[2]["status_class"], "5xx")

    def test_usage_errors_are_json(self):
        for argv in (["ls", "--code", "abc"], ["ls", "--fields", "nope"], ["ls", "--since", "yesterday"],
                     ["ls", "--limit", "0"], ["bogus"], ["show"]):
            envelope = self.run_json(*argv, expected_exit=chucker.Exit.USAGE)
            self.assertFalse(envelope["ok"])
            self.assertEqual(envelope["error"]["code"], "usage")

    def test_rejects_injection_in_package_and_serial(self):
        self.run_json("ls", "--package", "com.x;rm -rf /", expected_exit=chucker.Exit.USAGE)
        self.run_json("ls", "--serial", "emu $(id)", expected_exit=chucker.Exit.USAGE)

    # show / body / redaction

    def test_show_redacts_secrets_everywhere(self):
        code, out, _ = self.run_cli("show", "1")
        self.assertEqual(code, 0)
        self.assert_no_secrets(out)
        data = json.loads(out)["data"]
        request_headers = data["request"]["headers"]
        self.assertTrue(request_headers["Authorization"][0].startswith("<redacted len="))
        self.assertEqual(request_headers["Accept"], ["application/json"])
        body = data["response"]["body"]["value"]
        self.assertEqual(body["items"][0]["name"], "Melk")
        self.assertIn("<redacted", body["note"])
        self.assertIn("#1.request.headers.Authorization", json.loads(out)["meta"]["redacted"])

    def test_fingerprints_match_within_one_output(self):
        data = self.run_json("show", "1")["data"]
        cookie = data["request"]["headers"]["Cookie"][0]
        set_cookie = data["response"]["headers"]["Set-Cookie"][0]
        self.assertEqual(cookie, set_cookie)

    RAW_HOST = "api.staging.example.com"

    def add_allowlisted_row(self, host=RAW_HOST, tid=5):
        conn = sqlite3.connect(self.db)
        conn.execute(
            "INSERT INTO transactions (id, requestDate, method, host, path, url, requestHeaders, responseCode, "
            "isRequestBodyEncoded, isResponseBodyEncoded, graphQlDetected) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0)",
            (tid, NOW_MS - 7_200_000, "GET", host, "/v1/me", f"https://{host}/v1/me",
             headers(Authorization=f"Bearer {RAW_HOST_TOKEN}"), 200))
        conn.commit()
        conn.close()

    def test_everything_is_masked_by_default_whatever_the_host(self):
        self.add_allowlisted_row()
        code, out, err = self.run_cli("show", "5")
        self.assertEqual(code, 0)
        self.assertNotIn(RAW_HOST_TOKEN, out)
        self.assertEqual(json.loads(out)["meta"]["redaction"], "on")
        self.assertNotIn("unsafe_raw_allowlist", json.loads(out)["meta"])
        self.assertNotIn("WARNING", err)

    def test_unsafe_raw_unmasks_only_listed_hosts(self):
        self.add_allowlisted_row()
        code, out, err = self.run_cli("show", "5", "--unsafe-raw", self.RAW_HOST.upper())
        self.assertEqual(code, 0)
        envelope = json.loads(out)
        self.assertEqual(envelope["data"]["request"]["headers"]["Authorization"], [f"Bearer {RAW_HOST_TOKEN}"])
        self.assertEqual(envelope["meta"]["unsafe_raw_allowlist"], [self.RAW_HOST])
        self.assertEqual(envelope["meta"]["raw_hosts"], [self.RAW_HOST])
        self.assertEqual(envelope["meta"]["redaction"], "allowlist-raw")
        self.assertIn(f"rows from {self.RAW_HOST} are UNREDACTED", err)
        code, out, _ = self.run_cli("show", "1", "--unsafe-raw", self.RAW_HOST)
        self.assert_no_secrets(out)
        self.assertEqual(json.loads(out)["meta"]["masked_hosts"], ["api.example.com"])
        self.assertEqual(json.loads(out)["meta"]["raw_hosts"], [])

    def test_ls_reports_raw_and_masked_hosts(self):
        self.add_allowlisted_row()
        code, out, _ = self.run_cli("ls", "--unsafe-raw", self.RAW_HOST)
        self.assert_no_secrets(out)
        meta = json.loads(out)["meta"]
        self.assertEqual(meta["raw_hosts"], [self.RAW_HOST])
        self.assertEqual(meta["masked_hosts"], ["api.example.com", "static.example.com", "www.example.com"])

    def test_bare_or_invalid_unsafe_raw_is_a_usage_error(self):
        for argv in (["--unsafe-raw"], ["--unsafe-raw", ""], ["--unsafe-raw", " , "], ["--unsafe-raw", "*"],
                     ["--unsafe-raw", "*.com"], ["--unsafe-raw", "api.example.com/path"],
                     ["--unsafe-raw", "a b"]):
            envelope = self.run_json("show", "1", *argv, expected_exit=chucker.Exit.USAGE)
            self.assertEqual(envelope["error"]["code"], "usage", argv)
        hint = self.run_json("show", "1", "--unsafe-raw", expected_exit=chucker.Exit.USAGE)["error"]["hint"]
        self.assertIn("exact hosts", hint)

    def test_unsafe_raw_accepts_lists_repeats_and_the_env_var(self):
        self.add_allowlisted_row()
        self.add_allowlisted_row("other.example.com", 6)
        for argv, env in ((["--unsafe-raw", f"x.example.com,{self.RAW_HOST}"], {}),
                          (["--unsafe-raw", "x.example.com", "--unsafe-raw", self.RAW_HOST], {}),
                          ([], {"CHUCKER_UNSAFE_RAW_HOSTS": f" {self.RAW_HOST} , x.example.com"})):
            with mock.patch.dict(os.environ, env):
                ids = {row["id"]: row for row in self.run_json("ls", *argv)["data"]}
                self.assertIn(RAW_HOST_TOKEN, self.run_cli("show", "5", *argv)[1], argv or env)
                self.assertNotIn(RAW_HOST_TOKEN, self.run_cli("show", "6", *argv)[1], argv or env)
            self.assertEqual(set(ids), {1, 2, 3, 4, 5, 6})

    def test_wildcard_matches_subdomains_only(self):
        self.add_allowlisted_row("example.com", 5)
        self.add_allowlisted_row("api.staging.example.com", 6)
        self.add_allowlisted_row("evil-example.com", 7)
        argv = ["--unsafe-raw", "*.example.com"]
        self.assertNotIn(RAW_HOST_TOKEN, self.run_cli("show", "5", *argv)[1])
        self.assertIn(RAW_HOST_TOKEN, self.run_cli("show", "6", *argv)[1])
        self.assertNotIn(RAW_HOST_TOKEN, self.run_cli("show", "7", *argv)[1])
        self.assertFalse(chucker.host_allowed("example.com.evil.net", frozenset({"*.example.com"})))
        self.assertFalse(chucker.host_allowed(None, frozenset({"*.example.com"})))

    def test_curl_uses_raw_values_only_for_listed_hosts(self):
        self.add_allowlisted_row()
        raw = self.run_json("curl", "5", "--unsafe-raw", self.RAW_HOST)["data"]
        self.assertIn(RAW_HOST_TOKEN, raw["command"])
        self.assertEqual(raw["placeholders"], [])
        masked = self.run_json("curl", "5", "--unsafe-raw", "other.example.com")["data"]
        self.assertNotIn(RAW_HOST_TOKEN, masked["command"])
        self.assertEqual(masked["placeholders"], ["Authorization"])
        code, out, _ = self.run_cli("curl", "2", "--unsafe-raw", self.RAW_HOST)
        self.assert_no_secrets(out)

    def test_har_export_honours_the_allowlist(self):
        self.add_allowlisted_row()
        out = self.dir / "raw.har"
        self.run_json("export", "--out", str(out), "--unsafe-raw", self.RAW_HOST)
        har = out.read_text()
        self.assertIn(RAW_HOST_TOKEN, har)
        self.assert_no_secrets(har)

    def test_filters_cannot_be_used_as_secret_oracle(self):
        for argv in (["--body-contains", "hunter"], ["--body-contains", "jan@example"], ["--path", "querysecret"]):
            for raw in ([], ["--unsafe-raw", "unrelated.example.com"]):
                self.assertEqual(self.run_json("ls", *argv, *raw)["data"], [], argv + raw)
        self.assertEqual([row["id"] for row in self.run_json("ls", "--path", "page=1")["data"]], [1])

    def test_snapshot_command_is_gone(self):
        self.run_json("snapshot", "--out", str(self.dir / "x.db"), expected_exit=chucker.Exit.USAGE)

    def test_url_headers_messages_and_errors_are_redacted(self):
        for argv in (["show", "1"], ["show", "2"], ["show", "3"], ["curl", "2"]):
            code, out, _ = self.run_cli(*argv)
            self.assertEqual(code, 0, argv)
            self.assert_no_secrets(out)
        location = self.run_json("show", "1")["data"]["response"]["headers"]["Location"][0]
        self.assertIn("state=ok", location)
        self.assertIn("tab=1", self.run_json("curl", "2")["data"]["command"])

    def test_opaque_json_credentials_are_redacted(self):
        body = self.run_json("body", "1")["data"]["value"]
        self.assertTrue(body["apiKey"].startswith("<redacted"))
        self.assertTrue(body["sessionId"].startswith("<redacted"))

    def test_curl_replays_decoded_urls_and_skips_encoding_headers(self):
        command = self.run_json("curl", "2")["data"]["command"]
        self.assertIn("q=green%20beans", command)
        self.assertNotIn("Content-Encoding", command)

    def test_redaction_is_linear_on_long_delimiter_free_values(self):
        redactor = chucker.Redactor()
        started = time.monotonic()
        redactor.text("a" * 200_000 + "+b.c-d" * 20_000, "#x")
        redactor.text("x" * 200_000 + ":", "#x")
        self.assertLess(time.monotonic() - started, 5)

    def test_nested_graphql_arguments_are_redacted_but_siblings_stay_readable(self):
        nested = self.run_json("body", "2", "--side", "request", "--select", "nested")["data"]["value"]
        self.assertIn('keep: "visible"', nested)
        self.assertIn("input: {password: ", nested)

    def test_captured_url_redacts_userinfo_and_fragments_but_keeps_the_host(self):
        url = self.run_json("show", "3")["data"]["url"]
        self.assertIn("@www.example.com/red?page=1#access_token=", url)
        fragment_only = chucker.Redactor().captured_url("https://api.example.com/cb#access_token=fragonly963", "#t")
        self.assertNotIn("fragonly963", fragment_only)

    def test_decoded_userinfo_with_url_delimiters_in_the_password_is_masked(self):
        redactor = chucker.Redactor()
        for delimiter in "#?/":
            url = f"https://alice:probe852{delimiter}suffix@api.example.com/cb?page=1"
            redacted = redactor.captured_url(url, "#t")
            self.assertNotIn("probe852", redacted, delimiter)
            self.assertIn("@api.example.com/cb", redacted, delimiter)
        self.assertIn("api.example.com/x?email=", redactor.captured_url("https://api.example.com/x?email=a@b.com", "#t"))

    def test_query_redaction_is_linear_in_the_number_of_fields(self):
        body = "&".join(f"f{index}=v{index}" for index in range(60_000)) + "&password=formpw"
        started = time.monotonic()
        for decoded in (False, True):
            self.assertNotIn("formpw", chucker.Redactor().query(body, "#t", decoded=decoded))
        self.assertLess(time.monotonic() - started, 5)

    def test_show_missing_id(self):
        envelope = self.run_json("show", "999", expected_exit=chucker.Exit.NOT_FOUND)
        self.assertEqual(envelope["error"]["code"], "not_found")

    def test_binary_body_is_never_dumped(self):
        data = self.run_json("show", "4")["data"]
        self.assertEqual(data["response"]["body"]["kind"], "binary")
        self.assertEqual(data["response"]["image"], {"size": 80})

    def test_truncation_is_reported(self):
        envelope = self.run_json("show", "2", "--max-chars", "50")
        body = envelope["data"]["response"]["body"]
        self.assertEqual(body["kind"], "json_truncated")
        self.assertEqual(len(body["value"]), 50)
        self.assertIn("#2.response.body", envelope["meta"]["truncated"])

    def test_body_select(self):
        self.assertEqual(self.run_json("body", "1", "--select", "items[0].name")["data"]["value"], "Melk")
        redacted = self.run_json("body", "2", "--side", "request", "--select", "variables.password")["data"]["value"]
        self.assertTrue(redacted.startswith("<redacted"))
        self.run_json("body", "1", "--select", "items[5].name", expected_exit=chucker.Exit.NOT_FOUND)
        self.run_json("body", "4", "--select", "a", expected_exit=chucker.Exit.NOT_FOUND)

    # curl / stats / export

    def test_curl_uses_placeholders(self):
        code, out, _ = self.run_cli("curl", "2")
        self.assertEqual(code, 0)
        self.assert_no_secrets(out)
        data = json.loads(out)["data"]
        self.assertIn("REDACTED", data["command"])
        self.assertNotIn("Content-Length", data["command"])
        self.assertEqual(data["placeholders"], ["Authorization"])

    def test_stats(self):
        data = self.run_json("stats")["data"]
        self.assertEqual(data["total"], 4)
        self.assertEqual(data["errors"], 2)
        self.assertEqual(data["by_status"], {"2xx": 2, "5xx": 1, "failed": 1})
        self.assertEqual(data["slowest"][0]["id"], 2)

    def test_export_writes_private_redacted_har_and_refuses_overwrite(self):
        out = self.dir / "traffic.har"
        envelope = self.run_json("export", "--out", str(out))
        self.assertEqual(envelope["data"]["entries"], 4)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        har = out.read_text()
        self.assert_no_secrets(har)
        self.assertEqual(json.loads(har)["log"]["version"], "1.2")
        self.run_json("export", "--out", str(out), expected_exit=chucker.Exit.USAGE)
        self.run_json("export", "--out", str(out), "--force")

    def test_clear_requires_confirmation(self):
        envelope = self.run_json("clear", "--package", FakeAdb.PACKAGE, expected_exit=chucker.Exit.USAGE,
                                 snapshot=False)
        self.assertEqual(envelope["error"]["code"], "confirmation_required")

    def test_device_commands_require_a_package(self):
        with mock.patch.dict(os.environ, clear=False) as env:
            env.pop("CHUCKER_PACKAGE", None)
            envelope = self.run_json("ls", expected_exit=chucker.Exit.USAGE, snapshot=False)
        self.assertEqual(envelope["error"]["message"], "Missing --package.")
        self.assertIn("applicationId", envelope["error"]["hint"])

    def test_table_format_strips_control_characters(self):
        code, out, _ = self.run_cli("ls", "--format", "table")
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", out)

    def test_jsonl_ends_with_meta_line(self):
        _, out, _ = self.run_cli("ls", "--format", "jsonl")
        lines = [json.loads(line) for line in out.splitlines()]
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[-1]["event"], "end")

    def test_snapshot_workdir_is_removed(self):
        created = []
        real_mkdtemp = tempfile.mkdtemp

        def tracking_mkdtemp(*args, **kwargs):
            created.append(real_mkdtemp(*args, **kwargs))
            return created[-1]

        with mock.patch.object(chucker.tempfile, "mkdtemp", tracking_mkdtemp):
            self.run_json("show", "1")
            self.run_json("show", "999", expected_exit=chucker.Exit.NOT_FOUND)
        self.assertEqual(len(created), 2)
        for directory in created:
            self.assertFalse(os.path.exists(directory))

    def test_schema_is_self_describing(self):
        data = self.run_json("schema", snapshot=False)["data"]
        self.assertIn("list", data["commands"])
        self.assertEqual(data["exit_codes"]["6"], "id or --select path not found")


REASON_EMAIL = "reason-user@example.com"


def insert_rows(path: Path, rows: list) -> None:
    conn = sqlite3.connect(path)
    conn.execute(CREATE_TABLE)
    for row in rows:
        row.setdefault("requestDate", NOW_MS - 1_000 * row["id"])
        row.setdefault("method", "POST")
        row.setdefault("host", "api.example.com")
        row.setdefault("responseContentType", "application/json")
        row.setdefault("isRequestBodyEncoded", 0)
        row.setdefault("isResponseBodyEncoded", 0)
        row.setdefault("graphQlDetected", 0)
        if isinstance(row.get("responseBody"), (dict, list)):
            row["responseBody"] = json.dumps(row["responseBody"])
        columns = ", ".join(row)
        conn.execute(f"INSERT INTO transactions ({columns}) VALUES ({', '.join('?' * len(row))})", list(row.values()))
    conn.commit()
    conn.close()


def graphql_row(tid, body, **extra):
    return dict(id=tid, path="/graphql", url="https://api.example.com/graphql", responseCode=200,
                graphQlDetected=1, graphQlOperationName=f"Op{tid}", responseBody=body, **extra)


def bff_row(tid, body, status=200, **extra):
    return dict(id=tid, method="GET", path=f"/api/v1/thing{tid}", url=f"https://api.example.com/api/v1/thing{tid}",
                responseCode=status, responseBody=body, **extra)


class ApplicationErrorTest(unittest.TestCase):
    """--errors and error_kind for GraphQL and BFF failures returned with HTTP 2xx."""

    EXPECTED_KINDS = {10: "graphql", 13: "graphql", 14: "bff", 15: "bff", 17: "http", 18: "http", 19: "transport",
                      20: "graphql", 22: "bff", 23: "bff"}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "errors.db"
        insert_rows(self.db, [
            graphql_row(10, {"data": {"product": None}, "errors": [{
                "message": f"Not found for {REASON_EMAIL} (Authorization: Bearer {JWT})", "path": ["product"],
                "extensions": {"code": "NOT_FOUND"}}]}),
            graphql_row(11, {"data": {"product": {"id": 1}}, "errors": []}),
            graphql_row(12, {"data": {"product": {"id": 1, "error": "deep field", "status": "FAILED"}}}),
            graphql_row(13, {"data": {"basketAdd": {"status": "FAILED", "errorMessage": "MAX_ITEMS_EXCEEDED"}}}),
            bff_row(14, {"errorCode": "ALREADY_APPROVED", "errorMessage": "Request was already approved"}),
            bff_row(15, {"success": False, "error": {"code": "OUT_OF_STOCK", "message": "Item unavailable"}}),
            bff_row(16, {"success": True, "items": [{"id": 1, "error": "none", "errors": ["x"], "status": "FAILED"}],
                         "error": None, "errorMessage": ""}),
            bff_row(17, {"message": "Unauthorized", "status": 401, "reason": "INVALID_TOKEN"}, status=401),
            bff_row(18, None, status=503, responseMessage="Service Unavailable"),
            bff_row(19, None, status=None, error="java.net.SocketTimeoutException: timeout"),
            graphql_row(20, '{"errors":[{"message":"cut off mid-str'),
            bff_row(21, '{"error": "cut off mid-str'),
            bff_row(22, {"type": "about:blank", "title": "Conflict", "status": 409, "detail": "Version mismatch"},
                    responseContentType="application/problem+json"),
            bff_row(23, {"errors": [{"field": "quantity", "message": "Must be positive"}]}),
            bff_row(24, "\x89PNG", isResponseBodyEncoded=1),
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = chucker.main([*argv, "--snapshot", str(self.db)])
        self.assertEqual(code, 0, stdout.getvalue() + stderr.getvalue())
        return stdout.getvalue()

    def rows(self, *argv):
        return {row["id"]: row for row in json.loads(self.run_cli("ls", "--limit", "100", *argv))["data"]}

    def test_errors_flags_transport_http_graphql_and_bff_failures(self):
        rows = self.rows("--errors", "--fields", "id,error_kind")
        self.assertEqual({tid: row["error_kind"] for tid, row in rows.items()}, self.EXPECTED_KINDS)

    def test_successful_and_unparseable_bodies_are_not_flagged(self):
        rows = self.rows()
        for tid in (11, 12, 16, 21, 24):
            self.assertIsNone(rows[tid]["error_kind"], tid)
            self.assertIsNone(rows[tid]["error_reason"], tid)

    def test_error_reason_combines_code_and_message(self):
        rows = self.rows("--errors")
        self.assertEqual(rows[13]["error_reason"], "basketAdd: MAX_ITEMS_EXCEEDED")
        self.assertEqual(rows[14]["error_reason"], "ALREADY_APPROVED: Request was already approved")
        self.assertEqual(rows[15]["error_reason"], "OUT_OF_STOCK: Item unavailable")
        self.assertEqual(rows[17]["error_reason"], "INVALID_TOKEN: Unauthorized")
        self.assertEqual(rows[18]["error_reason"], "Service Unavailable")
        self.assertEqual(rows[19]["error_reason"], "java.net.SocketTimeoutException: timeout")
        self.assertIsNone(rows[20]["error_reason"])
        self.assertEqual(rows[22]["error_reason"], "Version mismatch")
        self.assertEqual(rows[23]["error_reason"], "Must be positive")

    def test_error_reason_is_redacted(self):
        out = self.run_cli("ls", "--errors")
        self.assertNotIn(REASON_EMAIL, out)
        self.assertNotIn(JWT, out)
        envelope = json.loads(out)
        reason = next(row["error_reason"] for row in envelope["data"] if row["id"] == 10)
        self.assertTrue(reason.startswith("NOT_FOUND: Not found for <redacted"), reason)
        self.assertIn("#10.error_reason", envelope["meta"]["redacted"])
        selected = json.loads(self.run_cli("body", "10", "--select", "errors[0].message"))["data"]["value"]
        self.assertNotIn(REASON_EMAIL, selected)

    def test_long_reasons_are_capped(self):
        insert_rows(self.db, [bff_row(30, {"errorMessage": "x" * 500})])
        reason = self.rows("--errors")[30]["error_reason"]
        self.assertEqual(len(reason), chucker.MAX_REASON_CHARS)

    def test_stats_counts_errors_with_the_same_definition(self):
        data = json.loads(self.run_cli("stats"))["data"]
        self.assertEqual(data["errors"], len(self.EXPECTED_KINDS))
        self.assertEqual(data["errors_by_kind"], {"bff": 4, "graphql": 3, "http": 2, "transport": 1})

    def test_show_and_export_handle_cut_bodies(self):
        for tid in ("20", "21"):
            self.assertEqual(json.loads(self.run_cli("show", tid))["data"]["response"]["body"]["kind"], "omitted")
        out = Path(self.tmp.name) / "errors.har"
        self.run_cli("export", "--errors", "--out", str(out))
        self.assertEqual(len(json.loads(out.read_text())["log"]["entries"]), len(self.EXPECTED_KINDS))

    def test_schema_documents_error_kinds(self):
        data = json.loads(self.run_cli("schema"))["data"]
        self.assertIn("error_kind", data["summary_fields"])
        self.assertEqual(set(data["error_kinds"]) - {"error_reason"}, {"transport", "http", "graphql", "bff"})


class DeviceTest(unittest.TestCase):
    def fake_run(self, outputs):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            stdout = outputs(argv)
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=b"")

        return calls, run

    def test_choose_serial_errors(self):
        for listing, code in ((b"List of devices attached\n\n", "no_device"),
                              (b"List of devices attached\nemulator-5554\tdevice\nR58M\tdevice\n", "ambiguous_device"),
                              (b"List of devices attached\nR58M\tunauthorized\n", "no_device")):
            _, run = self.fake_run(lambda argv, listing=listing: listing)
            with mock.patch.object(chucker.subprocess, "run", run), mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("ANDROID_SERIAL", None)
                with self.assertRaises(chucker.CliError) as raised:
                    chucker.choose_serial("/adb", None)
            self.assertEqual(raised.exception.code, code)
            self.assertEqual(raised.exception.exit_code, chucker.Exit.DEVICE)

    def test_adb_argv_is_a_fixed_list_without_shell(self):
        calls, run = self.fake_run(lambda argv: chucker.SQLITE_MAGIC + b"rest")
        device = chucker.Device("/adb", "emulator-5554", "com.example.app.debug")
        with mock.patch.object(chucker.subprocess, "run", run):
            device.read_database_file("chucker.db")
        argv, kwargs = calls[0]
        self.assertEqual(argv, ["/adb", "-s", "emulator-5554", "exec-out", "run-as",
                                "com.example.app.debug", "cat", "databases/chucker.db"])
        self.assertNotIn("shell", kwargs)
        with self.assertRaises(ValueError):
            device.read_database_file("../../etc/passwd")

    def test_not_debuggable_maps_to_package_exit(self):
        def outputs(argv):
            return b"package:/data/app/base.apk" if "pm" in argv else b"run-as: package not debuggable: x"

        _, run = self.fake_run(outputs)
        device = chucker.Device("/adb", "emulator-5554", "com.example.app")
        with mock.patch.object(chucker.subprocess, "run", run):
            with self.assertRaises(chucker.CliError) as raised:
                device.list_databases()
        self.assertEqual(raised.exception.code, "not_debuggable")
        self.assertEqual(raised.exception.exit_code, chucker.Exit.PACKAGE)

    def test_clear_stops_before_deleting_when_force_stop_fails(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            failed = "force-stop" in argv
            return subprocess.CompletedProcess(argv, 1 if failed else 0, stdout=b"", stderr=b"boom" if failed else b"")

        device = chucker.Device("/adb", "emulator-5554", "com.example.app.debug")
        with mock.patch.object(chucker.subprocess, "run", run):
            with self.assertRaises(chucker.CliError) as raised:
                device.clear()
        self.assertEqual(raised.exception.code, "adb_failed")
        self.assertFalse(any("rm" in argv for argv in calls))

    def test_clear_reports_failed_delete(self):
        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1 if "rm" in argv else 0, stdout=b"", stderr=b"")

        device = chucker.Device("/adb", "emulator-5554", "com.example.app.debug")
        with mock.patch.object(chucker.subprocess, "run", run):
            with self.assertRaises(chucker.CliError) as raised:
                device.clear()
        self.assertEqual(raised.exception.exit_code, chucker.Exit.DEVICE)

    def test_snapshot_retries_when_a_checkpoint_changes_the_db(self):
        old, new = chucker.SQLITE_MAGIC + b"old", chucker.SQLITE_MAGIC + b"new"
        reads = iter([old, b"wal", new, new, b"wal2", new])
        device = chucker.Device("/adb", "emulator-5554", "com.example.app.debug")
        probe = chucker.Probe(files={"chucker.db": (None, ""), "chucker.db-wal": (None, "")})
        with mock.patch.object(device, "read_database_file", lambda name: next(reads)), \
                mock.patch.object(device, "probe", lambda: probe):
            copy = device.read_snapshot()
        self.assertEqual((copy.db, copy.wal, copy.signature), (new, b"wal2", None))

    def test_failed_wal_read_is_an_error_but_missing_wal_is_not(self):
        device = chucker.Device("/adb", "emulator-5554", "com.example.app.debug")
        cases = ((1, b"", b"run-as: couldn't stat: Permission denied", "error"),
                 (1, b"cat: databases/chucker.db-wal: No such file or directory", b"", None),
                 (0, b"", b"", None))
        for code, stdout, stderr, expected in cases:
            def run(argv, code=code, stdout=stdout, stderr=stderr, **kwargs):
                return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr=stderr)

            with mock.patch.object(chucker.subprocess, "run", run):
                if expected == "error":
                    with self.assertRaises(chucker.CliError) as raised:
                        device.read_database_file("chucker.db-wal")
                    self.assertEqual(raised.exception.code, "db_unreadable")
                else:
                    self.assertIsNone(device.read_database_file("chucker.db-wal"))

    def test_snapshot_gives_up_when_the_db_keeps_changing(self):
        counter = iter(range(100))
        device = chucker.Device("/adb", "emulator-5554", "com.example.app.debug")
        probe = chucker.Probe(files={"chucker.db": (None, "")})
        with mock.patch.object(device, "read_database_file", lambda name: str(next(counter)).encode()), \
                mock.patch.object(device, "probe", lambda: probe):
            with self.assertRaises(chucker.CliError) as raised:
                device.read_snapshot()
        self.assertEqual(raised.exception.code, "db_busy")


class FakeAdb:
    """Answers the CLI's adb calls from in-memory DB files, like toybox on a device would."""

    PACKAGE = "com.example.app"

    def __init__(self, db: bytes, wal: bytes = b"", tools=("gzip", "sha256sum")):
        self.files = {"chucker.db": db, "chucker.db-wal": wal}
        self.tools = set(tools)
        self.calls: list = []
        self.on_verify = None
        self.hash_output = None

    def stat_lines(self) -> str:
        return "".join(f"file {name} {len(data)} 42 2026-01-01 00:00:00.{len(data):09d} +0000\n"
                       for name, data in self.files.items() if data is not None)

    def __call__(self, argv, **kwargs):
        argv = argv[3:]  # drop adb -s serial
        self.calls.append(argv)
        if argv[:5] == ["shell", "run-as", self.PACKAGE, "sh", "-c"]:
            return self.done(self.script(shlex.split(argv[5])[0]).encode())
        if argv[:3] == ["exec-out", "run-as", self.PACKAGE]:
            name = argv[-1].split("/", 1)[1]
            data = self.files.get(name)
            if argv[3] == "gzip":
                if "gzip" not in self.tools:
                    return self.done(b"/system/bin/sh: gzip: inaccessible or not found\n")
                return self.done(gzip.compress(data) if data is not None else b"gzip: No such file\n")
            return self.done(data if data is not None else f"cat: {argv[-1]}: No such file or directory".encode())
        if argv[:2] == ["shell", "pm"]:
            return self.done(b"package:/data/app/base.apk")
        if argv[:3] == ["shell", "am", "force-stop"] or argv[:5] == ["shell", "run-as", self.PACKAGE, "rm", "-f"]:
            return self.done(b"")
        if argv[:4] == ["shell", "run-as", self.PACKAGE, "ls"]:
            return self.done(" ".join(name for name, data in self.files.items() if data is not None).encode())
        raise AssertionError(f"unexpected adb call {argv}")

    def script(self, script: str) -> str:
        if script == chucker.PROBE_SCRIPT:
            return "now 1700000000\n" + "".join(f"tool {tool}\n" for tool in sorted(self.tools)) + self.stat_lines()
        tool = next(tool for tool in chucker.HASH_TOOLS if script == chucker.verify_script(tool))
        if self.on_verify:
            self.on_verify()
        digest = hashlib.new(chucker.HASH_TOOLS[tool], self.files["chucker.db"]).hexdigest()
        return (self.hash_output or f"hash {digest}  databases/chucker.db") + "\n" + self.stat_lines()

    @staticmethod
    def done(stdout: bytes):
        return subprocess.CompletedProcess([], 0, stdout=stdout, stderr=b"")

    def transfers(self, name: str) -> int:
        return sum(1 for argv in self.calls if argv[0] == "exec-out" and argv[-1] == f"databases/{name}")


class DeviceTransferTest(unittest.TestCase):
    DB = chucker.SQLITE_MAGIC + b"main" * 1000
    WAL = chucker.WAL_MAGICS[0] + b"frames" * 100

    def read(self, fake: FakeAdb) -> "chucker.DeviceCopy":
        device = chucker.Device("/adb", "emulator-5554", FakeAdb.PACKAGE)
        with mock.patch.object(chucker.subprocess, "run", fake):
            return device.read_snapshot()

    def test_compressed_transfer_verified_by_on_device_hash_reads_each_file_once(self):
        fake = FakeAdb(self.DB, self.WAL)
        copy = self.read(fake)
        self.assertEqual((copy.db, copy.wal, copy.now_ms), (self.DB, self.WAL, 1_700_000_000_000))
        self.assertEqual((fake.transfers("chucker.db"), fake.transfers("chucker.db-wal")), (1, 1))
        self.assertTrue(all(argv[3] == "gzip" for argv in fake.calls if argv[0] == "exec-out"))
        self.assertEqual(len(fake.calls), 4)  # probe, db, wal, verify
        self.assertIsNotNone(copy.signature)

    def test_without_gzip_the_files_are_read_plainly(self):
        fake = FakeAdb(self.DB, self.WAL, tools=("sha1sum",))
        copy = self.read(fake)
        self.assertEqual((copy.db, copy.wal), (self.DB, self.WAL))
        self.assertTrue(all(argv[3] == "cat" for argv in fake.calls if argv[0] == "exec-out"))
        self.assertEqual(fake.transfers("chucker.db"), 1)

    def test_broken_gzip_output_falls_back_to_a_plain_read(self):
        fake = FakeAdb(self.DB, self.WAL)
        real = fake.__call__

        def cut_gzip(argv, **kwargs):
            result = real(argv, **kwargs)
            if "gzip" in argv:
                result.stdout = result.stdout[:20]
            return result

        device = chucker.Device("/adb", "emulator-5554", FakeAdb.PACKAGE)
        with mock.patch.object(chucker.subprocess, "run", cut_gzip):
            copy = device.read_snapshot()
        self.assertEqual((copy.db, copy.wal), (self.DB, self.WAL))
        self.assertIn(["exec-out", "run-as", FakeAdb.PACKAGE, "cat", "databases/chucker.db"], fake.calls)

    def test_without_a_hash_tool_the_main_file_is_read_twice(self):
        fake = FakeAdb(self.DB, self.WAL, tools=("gzip",))
        copy = self.read(fake)
        self.assertEqual(copy.db, self.DB)
        self.assertEqual(fake.transfers("chucker.db"), 2)
        self.assertIsNone(copy.signature)

    def test_unparseable_hash_output_falls_back_to_a_full_read(self):
        fake = FakeAdb(self.DB, self.WAL)
        fake.hash_output = "sha256sum: databases/chucker.db: Permission denied"
        copy = self.read(fake)
        self.assertEqual(copy.db, self.DB)
        self.assertEqual(fake.transfers("chucker.db"), 2)

    def test_hash_mismatch_after_a_checkpoint_retries(self):
        fake = FakeAdb(self.DB, self.WAL)
        changed = chucker.SQLITE_MAGIC + b"checkpointed"

        def checkpoint():
            fake.files.update({"chucker.db": changed, "chucker.db-wal": b""})
            fake.on_verify = None

        fake.on_verify = checkpoint
        copy = self.read(fake)
        self.assertEqual((copy.db, copy.wal), (changed, None))
        self.assertEqual(fake.transfers("chucker.db"), 2)
        self.assertEqual(fake.transfers("chucker.db-wal"), 1)  # empty after the checkpoint: skipped

    def test_db_that_keeps_changing_gives_up(self):
        fake = FakeAdb(self.DB)
        fake.on_verify = lambda: fake.files.update({"chucker.db": fake.files["chucker.db"] + b"x"})
        with self.assertRaises(chucker.CliError) as raised:
            self.read(fake)
        self.assertEqual(raised.exception.code, "db_busy")

    def test_missing_or_empty_wal_is_not_transferred(self):
        for wal in (b"", None):
            fake = FakeAdb(self.DB, wal)
            copy = self.read(fake)
            self.assertIsNone(copy.wal)
            self.assertEqual(fake.transfers("chucker.db-wal"), 0)

    def test_failed_probe_reports_the_specific_error(self):
        def run(argv, **kwargs):
            if "pm" in argv:
                return FakeAdb.done(b"package:/data/app/base.apk")
            return FakeAdb.done(b"run-as: package not debuggable: com.example.app")

        device = chucker.Device("/adb", "emulator-5554", FakeAdb.PACKAGE)
        with mock.patch.object(chucker.subprocess, "run", run):
            with self.assertRaises(chucker.CliError) as raised:
                device.read_snapshot()
        self.assertEqual(raised.exception.code, "not_debuggable")

    def test_missing_db_is_no_database(self):
        with self.assertRaises(chucker.CliError) as raised:
            self.read(FakeAdb(None))
        self.assertEqual(raised.exception.exit_code, chucker.Exit.NO_DB)

    def test_remote_scripts_are_fixed_and_quoted_once(self):
        fake = FakeAdb(self.DB, self.WAL)
        self.read(fake)
        scripts = [argv[5] for argv in fake.calls if argv[0] == "shell"]
        self.assertEqual(scripts[0], shlex.quote(chucker.PROBE_SCRIPT))
        self.assertEqual(scripts[1], shlex.quote(chucker.verify_script("sha256sum")))
        with self.assertRaises(ValueError):
            chucker.verify_script("rm -rf /;")


class SnapshotCacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"XDG_CACHE_HOME": str(self.home)})
        self.env.start()
        self.db = self.home / "source.db"
        build_fixture(self.db)
        self.fake = FakeAdb(self.db.read_bytes(), b"")
        self.device = mock.patch.object(chucker, "choose_serial", lambda adb, serial: "emulator-5554")
        self.adb = mock.patch.object(chucker, "resolve_adb", lambda: "/adb")
        self.run = mock.patch.object(chucker.subprocess, "run", self.fake)
        for patcher in (self.device, self.adb, self.run):
            patcher.start()

    def tearDown(self):
        for patcher in (self.device, self.adb, self.run, self.env):
            patcher.stop()
        self.tmp.cleanup()

    def cli(self, *argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = chucker.main([*argv, "--package", FakeAdb.PACKAGE])
        self.assertEqual(code, 0, stdout.getvalue())
        return json.loads(stdout.getvalue())

    def cache_dir(self) -> Path:
        return self.home / "chucker-cli"

    def test_cache_is_off_by_default(self):
        meta = self.cli("ls")["meta"]
        self.assertNotIn("cache", meta)
        self.assertFalse(self.cache_dir().exists())

    def test_unchanged_device_files_are_reused_privately(self):
        self.assertEqual(self.cli("ls", "--cache-ttl", "30")["meta"]["cache"], "stored")
        transfers = self.fake.transfers("chucker.db")
        envelope = self.cli("show", "1", "--cache-ttl", "30")
        self.assertEqual(envelope["meta"]["cache"], "hit")
        self.assertEqual(envelope["data"]["id"], 1)
        self.assertEqual(self.fake.transfers("chucker.db"), transfers)
        self.assertEqual(stat.S_IMODE(self.cache_dir().stat().st_mode), 0o700)
        for path in self.cache_dir().iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assert_no_secrets_on_output(envelope)

    def assert_no_secrets_on_output(self, envelope):
        text = json.dumps(envelope)
        for secret in SECRETS:
            self.assertNotIn(secret, text)

    def test_changed_device_files_miss_the_cache(self):
        self.cli("ls", "--cache-ttl", "30")
        self.fake.files["chucker.db-wal"] = chucker.WAL_MAGICS[0] + b"x" * 10
        with mock.patch.object(chucker.Device, "fetch", lambda device, name, compress: (
                self.fake.files["chucker.db"] if name == "chucker.db" else None)):
            self.assertNotEqual(self.cli("ls", "--cache-ttl", "30")["meta"]["cache"], "hit")

    def test_env_enables_the_cache_and_expired_entries_are_deleted(self):
        with mock.patch.dict(os.environ, {"CHUCKER_CACHE_TTL": "30"}):
            self.assertEqual(self.cli("ls")["meta"]["cache"], "stored")
        meta_file = next(self.cache_dir().glob("*.json"))
        meta_file.write_text(json.dumps({**json.loads(meta_file.read_text()), "expires": time.time() - 1}))
        self.cli("schema")  # any command purges expired entries
        self.assertEqual(list(self.cache_dir().iterdir()), [])

    def test_clear_deletes_the_cache_entry(self):
        self.cli("ls", "--cache-ttl", "30")
        self.cli("clear", "--yes")
        self.assertEqual(list(self.cache_dir().iterdir()), [])

    def test_insecure_cache_dir_is_never_used(self):
        self.cache_dir().mkdir(mode=0o755)
        self.assertEqual(self.cli("ls", "--cache-ttl", "30")["meta"].get("cache"), None)
        self.assertEqual(list(self.cache_dir().iterdir()), [])

    def test_symlinked_cache_dir_is_never_used(self):
        target = self.home / "elsewhere"
        target.mkdir(mode=0o700)
        self.cache_dir().symlink_to(target)
        self.cli("ls", "--cache-ttl", "30")
        self.assertEqual(list(target.iterdir()), [])

    def test_cache_ttl_is_bounded(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(chucker.main(["ls", "--cache-ttl", "100000"]), chucker.Exit.USAGE)
        with mock.patch.dict(os.environ, {"CHUCKER_CACHE_TTL": "soon"}), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(chucker.main(["ls"]), chucker.Exit.USAGE)


class LocalSnapshotTest(unittest.TestCase):
    def test_snapshot_without_wal_is_read_in_place_and_left_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "fixture.db"
            build_fixture(db)
            before = (db.read_bytes(), db.stat().st_mtime_ns)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(chucker.main(["ls", "--snapshot", str(db)]), 0)
            self.assertEqual(len(json.loads(stdout.getvalue())["data"]), 4)
            self.assertEqual((db.read_bytes(), db.stat().st_mtime_ns), before)
            self.assertEqual(sorted(path.name for path in Path(tmp).iterdir()), ["fixture.db"])

    def test_snapshot_with_wal_is_consolidated_in_a_private_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "live.db"
            conn = sqlite3.connect(db)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(CREATE_TABLE)
            conn.execute("INSERT INTO transactions (id, isRequestBodyEncoded, isResponseBodyEncoded, graphQlDetected) "
                         "VALUES (7, 0, 0, 0)")
            conn.commit()
            wal_copy = (Path(tmp) / "live.db-wal").read_bytes()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(chucker.main(["ls", "--snapshot", str(db)]), 0)
            conn.close()
            self.assertEqual([row["id"] for row in json.loads(stdout.getvalue())["data"]], [7])
            self.assertTrue(wal_copy)


class TailAndLimitTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(CREATE_TABLE)
        self.snap = chucker.Snapshot(self.conn, Path(), "", NOW_MS, None, None)

    def tearDown(self):
        self.conn.close()

    def insert(self, tid, status=None, error=None):
        self.conn.execute("INSERT OR REPLACE INTO transactions (id, responseCode, error, isRequestBodyEncoded, "
                          "isResponseBodyEncoded, graphQlDetected) VALUES (?, ?, ?, 0, 0, 0)", (tid, status, error))

    def test_in_flight_request_is_reported_when_it_finishes_later(self):
        pending = set()
        self.insert(10)
        self.insert(11, status=500)
        finished, scanned = chucker.poll_finished(self.snap, 0, pending)
        self.assertEqual((finished, scanned, pending), ([11], 11, {10}))
        self.insert(10, status=503)
        finished, scanned = chucker.poll_finished(self.snap, scanned, pending)
        self.assertEqual((finished, pending), ([10], set()))

    def test_pending_rows_that_disappear_are_forgotten(self):
        pending = {7}
        self.insert(8, status=200)
        chucker.poll_finished(self.snap, 7, pending)
        self.assertEqual(pending, set())

    def test_limit_stops_reading_rows_early(self):
        for tid in range(1, 51):
            self.insert(tid, status=200)
        args = chucker.build_parser().parse_args(["export", "--out", "x.har", "--snapshot", "x.db"])
        checked = []

        def matches(row):
            checked.append(row["id"])
            return True

        with mock.patch.object(chucker, "text_filter", lambda args, redactor: matches):
            rows = chucker.query_rows(self.snap, args, chucker.Redactor(), "*", "id ASC", limit=3)
        self.assertEqual([row["id"] for row in rows], [1, 2, 3])
        self.assertEqual(checked, [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
