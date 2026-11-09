#!/usr/bin/env python3
"""End-to-end benchmark for the chucker CLI. Not part of the test suite (unittest only discovers test*.py).

    python3 cli/chucker/tests/bench_chucker.py --sizes 5,50,250 --runs 5
    python3 cli/chucker/tests/bench_chucker.py --serial emulator-5554 --package com.example.app   # adds device runs
    python3 cli/chucker/tests/bench_chucker.py --cli /path/to/other/cli.py                       # compare versions
    python3 cli/chucker/tests/bench_chucker.py --serial ... --package ... --env CHUCKER_CACHE_TTL=60  # opt-in cache

Synthetic DBs (example.com only) are cached in --workdir. Each command runs in a fresh process, like an agent's
calls; the child process times each phase (exclusive time) by wrapping the CLI's functions. With --serial, the
app is force-stopped, its chucker.db (+ -wal) is backed up, each synthetic DB is installed in turn, and the
backup is restored and the app relaunched at the end.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import random
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CLI = HERE.parent / "src" / "chucker_cli" / "cli.py"

# adb_transfer includes local gunzip; adb_verify the on-device hash plus the local one (or, in versions without
# it, nothing: their second full read counts as adb_transfer); adb_other is pm/ls/date in the old protocol.
PHASES = ("adb_list", "adb_probe", "adb_transfer", "adb_verify", "adb_other", "open", "query", "classify", "shape",
          "output", "startup")
MAX_BODY = 250_000
WORDS = ("milk", "bread", "cheese", "apple", "banana", "pasta", "rice", "coffee", "tea", "butter", "yoghurt",
         "tomato", "organic", "bonus", "fresh", "large", "pack", "price", "discount", "category")


# ---------------------------------------------------------------- synthetic data


def fake_items(rng: random.Random, count: int) -> list:
    return [{"id": rng.randrange(10**6), "title": " ".join(rng.choices(WORDS, k=4)),
             "price": {"now": round(rng.uniform(0.5, 20), 2), "was": None}, "error": None,
             "images": [f"https://img.example.com/{rng.randrange(10**8)}.png"],
             "tags": rng.choices(WORDS, k=3), "available": rng.random() > 0.1} for _ in range(count)]


def body_items(rng: random.Random) -> int:
    """Log-normal, median ~8 KB, a long tail up to (and beyond) Chucker's 250 KB cap."""
    return max(1, min(2000, int(rng.lognormvariate(3.2, 1.3))))


def make_row(rng: random.Random, tid: int, now_ms: int) -> dict:
    roll = rng.random()
    row = dict(id=tid, requestDate=now_ms - (100_000 - tid) * 1000, tookMs=rng.randrange(20, 1500), protocol="h2",
               host="api.example.com", scheme="https", responseContentType="application/json",
               isRequestBodyEncoded=0, isResponseBodyEncoded=0, graphQlDetected=0,
               requestHeaders=json.dumps([{"name": "Accept", "value": "application/json"},
                                          {"name": "X-Client", "value": "bench/1.0"}]),
               responseHeaders=json.dumps([{"name": "Content-Type", "value": "application/json"}]))
    if roll < 0.55:
        op = rng.choice(("ProductDetails", "Search", "Basket", "Bonus", "AddToBasket"))
        row.update(method="POST", path="/graphql", url="https://api.example.com/graphql", graphQlDetected=1,
                   graphQlOperationName=op, requestContentType="application/json",
                   requestBody=json.dumps({"operationName": op, "variables": {"id": tid, "query": "milk"},
                                           "query": f"query {op} {{ " + "field { id title } " * 40 + "}"}))
        if rng.random() < 0.04:
            body = {"data": None, "errors": [{"message": "Something went wrong", "path": ["x"],
                                              "extensions": {"code": "INTERNAL"}}]}
        else:
            body = {"data": {"items": fake_items(rng, body_items(rng))}}
        status = 200
    elif roll < 0.97:
        row.update(method=rng.choice(("GET", "GET", "POST")), path=f"/api/v1/products/{tid}?page=1",
                   url=f"https://api.example.com/api/v1/products/{tid}?page=1")
        kind = rng.random()
        if kind < 0.02:
            body, status = {"errorCode": "OUT_OF_STOCK", "errorMessage": "Item unavailable"}, 200
        elif kind < 0.05:
            body, status = {"message": "Internal error", "status": 500}, rng.choice((400, 404, 500, 503))
        else:
            body, status = {"items": fake_items(rng, body_items(rng)), "success": True}, 200
    elif roll < 0.99:
        row.update(method="GET", path=f"/img/{tid}.png", url=f"https://img.example.com/img/{tid}.png",
                   responseContentType="image/png", isResponseBodyEncoded=1)
        body, status = "\x89PNG" + "x" * rng.randrange(1000, 60_000), 200
    else:
        row.update(method="GET", path=f"/api/v1/thing/{tid}", url=f"https://api.example.com/api/v1/thing/{tid}",
                   error="java.net.SocketTimeoutException: timeout")
        return row
    text = body if isinstance(body, str) else json.dumps(body)
    row.update(responseCode=status, responseMessage="OK" if status < 400 else "Error",
               responseBody=text[:MAX_BODY], responsePayloadSize=len(text), requestPayloadSize=len(row.get("requestBody") or ""),
               responseDate=row["requestDate"] + row["tookMs"])
    return row


def build_db(path: Path, megabytes: int) -> dict:
    rng = random.Random(megabytes)
    now_ms = int(time.time() * 1000)
    tmp = path.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    sys.path.insert(0, str(HERE))
    from test_chucker import CREATE_TABLE  # imported here: it loads the CLI, which would skew child timings

    conn = sqlite3.connect(tmp)
    conn.execute(CREATE_TABLE)
    tid, target = 0, megabytes * 1024 * 1024
    while True:
        batch = [make_row(rng, tid + i + 1, now_ms) for i in range(50)]
        tid += len(batch)
        for row in batch:
            conn.execute(f"INSERT INTO transactions ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                         list(row.values()))
        conn.commit()
        if tmp.stat().st_size >= target:
            break
    conn.close()
    tmp.rename(path)
    return describe(path)


def describe(path: Path) -> dict:
    with contextlib.closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        error_id = conn.execute("SELECT id FROM transactions WHERE graphQlDetected = 1 AND responseBody LIKE "
                                "'{\"data\": null, \"errors\"%' ORDER BY id DESC LIMIT 1").fetchone()[0]
        big_id = conn.execute("SELECT id FROM transactions WHERE graphQlDetected = 1 "
                              "ORDER BY length(responseBody) DESC LIMIT 1").fetchone()[0]
    return {"rows": rows, "bytes": path.stat().st_size, "error_id": error_id, "big_id": big_id}


# ---------------------------------------------------------------- child: one instrumented CLI run


def child(cli: str, argv: list) -> None:
    started = float(os.environ["BENCH_T0"])
    spec = importlib.util.spec_from_file_location("chucker_bench_target", cli)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    totals = {phase: 0.0 for phase in PHASES}
    stack: list = []

    def timed(phase_of, function):
        def wrapper(*args, **kwargs):
            phase = phase_of(*args) if callable(phase_of) else phase_of
            frame = [time.perf_counter(), 0.0]
            stack.append(frame)
            try:
                return function(*args, **kwargs)
            finally:
                stack.pop()
                elapsed = time.perf_counter() - frame[0]
                totals[phase] += elapsed - frame[1]
                if stack:
                    stack[-1][1] += elapsed
        return wrapper

    def adb_phase(argv_, *rest):
        text = " ".join(map(str, argv_))
        if text.endswith(" devices"):
            return "adb_list"
        if "exec-out" in argv_:
            return "adb_transfer"
        if "hash $(" in text:
            return "adb_verify"
        if "echo \"now" in text or "echo now" in text:
            return "adb_probe"
        return "adb_other"

    module.run_process = timed(adb_phase, module.run_process)
    device = getattr(module, "Device", None)
    for name, phase in (("fetch", "adb_transfer"), ("verify", "adb_verify")):
        if device is not None and hasattr(device, name):
            setattr(device, name, timed(phase, getattr(device, name)))
    for name, phase in (("open_consolidated", "open"), ("write_private", "open"), ("classify", "classify"),
                        ("summarize", "shape"), ("body_view", "shape"), ("flat_body", "shape"),
                        ("select_path", "shape"), ("emit", "output"), ("load_cached", "open")):
        if hasattr(module, name):
            setattr(module, name, timed(phase, getattr(module, name)))
    stdout = io.StringIO()
    t0 = time.perf_counter()
    totals["startup"] = time.time() - started
    with contextlib.redirect_stdout(stdout):
        code = module.main(argv)
    total = time.perf_counter() - t0
    totals["query"] = max(0.0, total - sum(v for k, v in totals.items() if k not in ("query", "startup")))
    out = stdout.getvalue()
    ok = code == 0 and '"ok":true' in out.replace(" ", "")
    print(json.dumps({"phases": totals, "ok": ok, "code": code, "out_bytes": len(out),
                      "head": out[:200] if not ok else ""}), file=sys.__stderr__)


def run_child(cli: str, argv: list, env: dict) -> dict:
    started = time.time()
    proc = subprocess.run([sys.executable, __file__, "--child", cli, "--", *argv],
                          env={**env, "BENCH_T0": repr(started)}, capture_output=True, text=True)
    wall = time.time() - started
    line = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "{}"
    try:
        result = json.loads(line)
    except ValueError:
        result = {"ok": False, "head": proc.stderr[-400:], "phases": {}}
    result["wall"] = wall
    return result


# ---------------------------------------------------------------- device setup


class DeviceDb:
    """Backs up the app's chucker.db once, installs synthetic DBs, and restores the backup on exit."""

    def __init__(self, adb: str, serial: str, package: str, workdir: Path):
        self.adb, self.serial, self.package = adb, serial, package
        self.backup = workdir / f"backup-{serial}-{package}"

    def sh(self, *argv: str, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
        proc = subprocess.run([self.adb, "-s", self.serial, *argv], capture_output=True, **kwargs)
        if check and proc.returncode != 0:
            raise RuntimeError(f"{argv}: {proc.stderr.decode(errors='replace') or proc.stdout[:300]!r}")
        return proc

    def stop(self) -> None:
        self.sh("shell", "am", "force-stop", self.package)

    def __enter__(self) -> "DeviceDb":
        self.stop()
        self.backup.mkdir(parents=True, exist_ok=True)
        if (self.backup / "dirty").exists():
            # A previous run died with a synthetic DB installed: keep the real backup.
            return self
        for name in ("chucker.db", "chucker.db-wal"):
            proc = self.sh("exec-out", "run-as", self.package, "cat", f"databases/{name}", check=False)
            target = self.backup / name
            if proc.returncode == 0 and proc.stdout and b"No such file" not in proc.stdout[:200]:
                target.write_bytes(proc.stdout)
            elif target.exists():
                target.unlink()
        if not (self.backup / "chucker.db").exists():
            raise RuntimeError("no chucker.db on the device to back up; open the app first")
        return self

    def install(self, db: Path, wal: Path = None) -> None:
        self.stop()
        (self.backup / "dirty").touch()
        files = [(db, "chucker.db")] + ([(wal, "chucker.db-wal")] if wal else [])
        self.sh("shell", "run-as", self.package, "rm", "-f", "databases/chucker.db-wal", "databases/chucker.db-shm")
        for source, name in files:
            remote = f"/data/local/tmp/chucker-bench-{name}"
            self.sh("push", str(source), remote)
            self.sh("shell", "chmod", "644", remote)
            self.sh("shell", "run-as", self.package, "cp", remote, f"databases/{name}")
            self.sh("shell", "run-as", self.package, "chmod", "600", f"databases/{name}")
            self.sh("shell", "rm", "-f", remote)

    def __exit__(self, *exc) -> None:
        wal = self.backup / "chucker.db-wal"
        self.install(self.backup / "chucker.db", wal if wal.exists() else None)
        (self.backup / "dirty").unlink()
        self.sh("shell", "monkey", "-p", self.package, "-c", "android.intent.category.LAUNCHER", "1", check=False)


# ---------------------------------------------------------------- driver


def commands(info: dict) -> list:
    error_id, big_id = str(info["error_id"]), str(info["big_id"])
    return [
        ("ls", [["ls"]]),
        ("ls --errors", [["ls", "--errors"]]),
        ("body --select", [["body", error_id, "--select", "errors[0].message"]]),
        ("show", [["show", big_id]]),
        ("stats", [["stats"]]),
        ("agent: ls>body>show", [["ls", "--errors", "--limit", "5"], ["body", error_id, "--select", "errors[0]"],
                                 ["show", error_id]]),
    ]


def bench(cli: str, info: dict, mode_args: list, env: dict, runs: int) -> dict:
    results = {}
    for label, sequence in commands(info):
        samples = []
        for _ in range(runs):
            # Each sample starts cold; with a cache TTL set, later commands in a sequence may hit the cache.
            shutil.rmtree(Path(env["XDG_CACHE_HOME"]) / "chucker-cli", ignore_errors=True)
            phases = {phase: 0.0 for phase in PHASES}
            wall = 0.0
            for argv in sequence:
                result = run_child(cli, [*argv, *mode_args, "--format", "json"], env)
                if not result.get("ok"):
                    raise SystemExit(f"{label} {argv} failed: {result.get('head')}")
                wall += result["wall"]
                for phase, value in result["phases"].items():
                    phases[phase] = phases.get(phase, 0.0) + value
            samples.append((wall, phases))
        median_wall = statistics.median(sample[0] for sample in samples)
        results[label] = {"wall": median_wall,
                          "phases": {phase: statistics.median(s[1].get(phase, 0.0) for s in samples)
                                     for phase in PHASES}}
    return results


def print_table(title: str, results: dict) -> None:
    shown = [phase for phase in PHASES if any(r["phases"].get(phase, 0) >= 0.005 for r in results.values())]
    print(f"\n### {title}\n")
    print("| command | wall s | " + " | ".join(shown) + " |")
    print("|---|---:|" + "---:|" * len(shown))
    for label, result in results.items():
        cells = " | ".join(f"{result['phases'].get(phase, 0):.2f}" for phase in shown)
        print(f"| {label} | {result['wall']:.2f} | {cells} |")
    sys.stdout.flush()


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        dash = sys.argv.index("--")
        child(sys.argv[2], sys.argv[dash + 1:])
        return
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli", default=str(DEFAULT_CLI))
    parser.add_argument("--sizes", default="5,50,250", help="DB sizes in MB")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--workdir", default=str(Path(tempfile.gettempdir()) / "chucker-bench"))
    parser.add_argument("--serial", help="also benchmark on this device (it must run --package)")
    parser.add_argument("--package")
    parser.add_argument("--adb", default=os.environ.get("ADB") or shutil.which("adb") or "adb")
    parser.add_argument("--no-local", action="store_true")
    parser.add_argument("--env", action="append", default=[], help="extra KEY=VALUE for the CLI, e.g. a cache TTL")
    parser.add_argument("--json", help="also write all results here")
    args = parser.parse_args()
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "ADB": args.adb, "XDG_CACHE_HOME": str(workdir / "xdg-cache"),
           **dict(item.split("=", 1) for item in args.env)}
    if not any(item.startswith("CHUCKER_CACHE_TTL=") for item in args.env):
        env["CHUCKER_CACHE_TTL"] = "0"
    dbs = {}
    for size in (int(s) for s in args.sizes.split(",")):
        path = workdir / f"bench-{size}mb.db"
        dbs[size] = (path, describe(path) if path.exists() else build_db(path, size))
        print(f"{size} MB: {dbs[size][1]}", file=sys.stderr)
    print(f"cli: {args.cli}\nruns: {args.runs} (median)")
    everything = {}
    if not args.no_local:
        for size, (path, info) in dbs.items():
            results = bench(args.cli, info, ["--snapshot", str(path)], env, args.runs)
            everything[f"local {size}MB"] = results
            print_table(f"local --snapshot, {size} MB ({info['rows']} rows)", results)
    if args.serial:
        if not args.package:
            parser.error("--serial needs --package")
        device_env = {**env, "ANDROID_SERIAL": args.serial, "CHUCKER_PACKAGE": args.package}
        with DeviceDb(args.adb, args.serial, args.package, workdir) as device:
            for size, (path, info) in dbs.items():
                device.install(path)
                results = bench(args.cli, info, [], device_env, args.runs)
                everything[f"device {size}MB"] = results
                print_table(f"device {args.serial}, {size} MB ({info['rows']} rows)", results)
    if args.json:
        Path(args.json).write_text(json.dumps(everything, indent=2))


if __name__ == "__main__":
    main()
