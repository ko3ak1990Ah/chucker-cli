# chucker

Read-only, agent-first CLI over the HTTP/GraphQL traffic that
[Chucker](https://github.com/ChuckerTeam/chucker) captures in a debuggable Android app. Every command
prints one JSON envelope, and secrets are redacted before anything is printed.

- **Platforms:** macOS and Linux. Windows is untested.
- **Prerequisites:** Python 3.9+, `adb` (Android platform-tools), a connected emulator or device
  running a **debuggable** build that includes Chucker 4.x.
- **Dependencies:** Python standard library only.

## Install

```sh
uv tool install "git+https://github.com/ko3ak1990Ah/chucker-cli@chucker-v2.0.0#subdirectory=cli/chucker"
# or
pipx install "git+https://github.com/ko3ak1990Ah/chucker-cli@chucker-v2.0.0#subdirectory=cli/chucker"

chucker --version
chucker doctor
```

**Update:** re-run the install command with the new tag and `--force` (uv) or `pipx install --force`.
**Uninstall:** `uv tool uninstall chucker-cli` or `pipx uninstall chucker-cli`.

## Usage

```sh
chucker schema                       # machine-readable contract: commands, filters, exit codes, redaction
chucker doctor                       # adb, device, package, debuggable, DB checks
chucker ls --errors --since 5m       # failing calls, including GraphQL/BFF errors sent with HTTP 200
chucker ls --errors --fields id,path,status,graphql,error_kind,error_reason
chucker show 2973                    # full request/response
chucker body 2973 --select data.product.price
chucker body 2973 --select 'errors[0].message'
chucker curl 2973                    # secret headers become REDACTED placeholders
chucker stats --since 15m
chucker tail --count 10 --timeout 60 # JSONL stream
chucker export --out traffic.har     # redacted HAR, mode 0600
```

Pass the debuggable app id with `--package` (or `$CHUCKER_PACKAGE`), for example
`export CHUCKER_PACKAGE=com.example.app.debug`. Use `--serial` (or `$ANDROID_SERIAL`) when several devices are
connected. `--snapshot FILE` queries a local `chucker.db` and needs no package.

**Output:** stdout is always `{"ok": true, "data", "meta"}` or `{"ok": false, "error": {code, message, hint}}`.
Exit codes: `0` ok, `2` usage, `3` device, `4` package missing or not debuggable, `5` no Chucker DB,
`6` id or `--select` not found, `7` adb missing.

**Errors:** each summary row has `error_kind` and `error_reason`. `--errors` and the `stats` error count use the
same definition:

| `error_kind` | Meaning |
| --- | --- |
| `transport` | No response (DNS, timeout, TLS) |
| `http` | Status >= 400 |
| `graphql` | 2xx with a non-empty top-level `errors` array, or a root mutation result with `status: FAILED` and an `errorMessage` |
| `bff` | 2xx REST body with a top-level error envelope: `errors`, `error`, `errorCode`/`errorMessage`, `success: false`, or `application/problem+json` |

Only top-level keys count, so a data field named `error` isn't flagged. `error_reason` is a redacted
`code: message` of up to 200 characters, taken from `extensions.code` and `errors[0].message`, or from the
REST error body. It's null when unknown, for example when Chucker cut the body.

## What it changes

Nothing, except:
- `clear --yes` force-stops the app and deletes Chucker's database on the device.
- `export --out FILE` writes a file (mode 0600, never overwrites without `--force`).

Each command copies the DB into a private temp folder (0700/0600) and deletes it afterwards. The copy
is gzip-compressed on the device when `gzip` is available, and checked against an on-device `sha256sum`
instead of being read twice. It makes no network calls.

**Opt-in cache:** `--cache-ttl SECONDS` (or `CHUCKER_CACHE_TTL`, at most 600, default off) keeps the copy
in `~/.cache/chucker-cli/` (or `$XDG_CACHE_HOME`) and reuses it while the files on the device are unchanged.
Consecutive commands then skip the transfer. The cached copy is **unredacted** and stays on disk until it
expires: every command deletes expired entries, and `clear --yes` deletes the device's entry. The
directory must be yours with mode 0700, or the cache stays off. `meta.cache` reports `hit`, `stored` or
`miss`.

## Security

- **Redaction is on for every host by default.** The tool doesn't guess which environments are safe. It
  covers auth headers, cookies, tokens, JWTs, emails, device/installation ids, PII-named JSON keys and
  secret query parameters. Masks look like `<redacted len=N fp:xxxxxxxx>`; the fingerprint is only
  comparable within one command's output.
- `--unsafe-raw HOST` unmasks rows from the hosts you list, and only those. Repeat the flag or separate
  hosts with commas, or set `CHUCKER_UNSAFE_RAW_HOSTS`. Matching is exact and case-insensitive, and
  `*.example.com` matches its subdomains but not `example.com` itself. A bare `--unsafe-raw` is a usage
  error. It prints a warning; `meta.unsafe_raw_allowlist`, `meta.raw_hosts` (unmasked) and
  `meta.masked_hosts` report what happened. `show`, `body`, `ls`, `curl` and `export` follow the same list.
- `--path` and `--body-contains` search the redacted view, so they can't be used to guess secrets.
- `adb` is called with fixed argument lists, never through a local shell; `--package` and `--serial` are
  validated. The only device-side scripts are fixed strings that read Chucker's files as the app user.
- Only debuggable builds can be read (`run-as`). Chucker defaults apply: bodies over 250 KB are cut at
  capture time and entries expire after a week.

## Develop

```sh
cd cli/chucker
python3 -m unittest discover tests     # stdlib only, no device needed
uv tool install --force --editable .   # try local changes as `chucker`
```

Release: bump `VERSION` in `src/chucker_cli/cli.py`, merge to `main`, then tag `chucker-vX.Y.Z`.
