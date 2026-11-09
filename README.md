# Chucker CLI

Let your AI coding agent check what your Android app really sent, with a few hundred tokens instead of a pile
of screenshots.

[Chucker](https://github.com/ChuckerTeam/chucker) records every HTTP call your debug app makes. This repository
adds a small read-only command-line tool, `chucker`, that reads that recording over `adb` and answers in compact
JSON, with tokens, cookies and personal data masked. It also ships an agent skill that tells the agent when and
how to use it. This is an independent project, not affiliated with the Chucker team.

- **Fewer tokens:** an overview of the latest 20 calls is about 1,700 tokens (about 470 with `--fields`). Reading
  one call from Chucker's screen takes 8 or more screenshots, at roughly 3,400 tokens each.
- **Faster:** about half a second per command on a typical debug session.
- **Verifies what the screen can't show:** the real order of a list, the variables a request carried, a GraphQL
  error hidden behind HTTP 200.
- **Safe by default:** every host is masked unless you name it with `--unsafe-raw`.

## Install

The skill, for Claude Code, Codex, Cursor, OpenCode and other agents:

```sh
npx skills add ko3ak1990Ah/chucker-cli
```

The CLI (Python 3.9+, `adb`, no other dependencies):

```sh
uv tool install "git+https://github.com/ko3ak1990Ah/chucker-cli@chucker-v2.0.0#subdirectory=cli/chucker"
# or: pipx install "git+https://github.com/ko3ak1990Ah/chucker-cli@chucker-v2.0.0#subdirectory=cli/chucker"
```

Then, with an emulator or device running a debug build that includes Chucker:

```sh
export CHUCKER_PACKAGE=com.example.app.debug   # your debug build's applicationId
chucker doctor
chucker ls --errors --since 5m
```

See [cli/chucker/README.md](cli/chucker/README.md) for every command, the output contract and the security
model, and [skills/chucker/SKILL.md](skills/chucker/SKILL.md) for what the agent is told.

## Try it

[examples/android-demo](examples/android-demo) is a small app and mock server with two planted bugs that only the
traffic reveals.

## Layout

| Path | What |
|---|---|
| `cli/chucker` | the CLI: one standard-library Python package, with tests |
| `skills/chucker` | the agent skill, installed as-is by `npx skills` |
| `examples/android-demo` | demo app and mock server |

## License

[MIT](LICENSE)
