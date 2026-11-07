#!/usr/bin/env python3
"""One `rad.hello` handshake with a freedom-radicled binary, spawned as main
spawns it (design 0008, "Spawn and lock"). release-radicled.yml runs it on
the binary of each archive it builds, where the runner can execute it.

    python3 scripts/radicled-hello.py <binary>

It runs `serve --home <tmp>/R/1 --lock-dir <tmp>/locks --network direct`
with the environment cleared but for `HOME`, an empty directory of its own,
and on Windows `SystemRoot`, as radicled's own tests do. It sends `rad.hello`
in one JSON frame and checks the reply:

- `protocol` is 1, and `service_version` is freedom-radicled's version in
  services/freedom-radicled/Cargo.lock (which `--locked` holds to its
  `Cargo.toml`);
- `libradicle` names the version and commit that lockfile pins;
- `recipient` is 32 bytes of base64, `network` is `{"mode": "direct"}`, and
  `confinement` is an object, printed for the log.

Then it closes stdin, and the service must exit 0 (stdin EOF). Standard
library only: it runs on every runner's own Python.
"""

import base64
import json
import os
import pathlib
import queue
import struct
import subprocess
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVICE = ROOT / "services" / "freedom-radicled"
LIBRADICLE = "git+https://github.com/solardev-xyz/libradicle?rev="
KIND_JSON = 0x01
# The service's own handshake deadline is 10 s from its start (0008); these
# leave room for a slow runner, and fail rather than hang.
REPLY_TIMEOUT = 60
EXIT_TIMEOUT = 60


class HelloError(Exception):
    pass


def packages(lock):
    """Each `[[package]]` of a Cargo.lock as its `key = "value"` fields."""
    for block in lock.split("[[package]]")[1:]:
        fields = {}
        for line in block.splitlines():
            key, sep, value = line.partition(" = ")
            if sep and value.startswith('"') and value.endswith('"'):
                fields[key.strip()] = value[1:-1]
        yield fields


def expected():
    """The version and the libradicle pin the binary must report, from the
    lockfile, which records both. Parsed by hand, not with tomllib: a
    runner's Python may predate it (macOS's system Python is 3.9)."""
    lock = (SERVICE / "Cargo.lock").read_text(encoding="utf-8")
    own = [p for p in packages(lock) if p.get("name") == "freedom-radicled" and "source" not in p]
    pinned = [p for p in packages(lock) if p.get("name") == "libradicle"]
    if len(own) != 1:
        raise HelloError("Cargo.lock has no single freedom-radicled package")
    if len(pinned) != 1 or not pinned[0].get("source", "").startswith(LIBRADICLE):
        raise HelloError(f"Cargo.lock pins libradicle {len(pinned)} times, or not by commit")
    commit = pinned[0]["source"].rsplit("#", 1)[-1]
    return own[0]["version"], {"version": pinned[0]["version"], "git_commit": commit}


def frame(message):
    payload = json.dumps(message).encode("utf-8")
    # The length counts the kind byte (fc-protocol's frame header).
    return struct.pack(">I", len(payload) + 1) + bytes([KIND_JSON]) + payload


def read_exactly(stream, count):
    data = b""
    while len(data) < count:
        chunk = stream.read(count - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def read_frames(stream, out):
    """Each frame from `stream` onto `out`, then None at EOF."""
    while True:
        header = read_exactly(stream, 5)
        if header is None:
            out.put(None)
            return
        length, kind = struct.unpack(">I", header[:4])[0], header[4]
        payload = read_exactly(stream, length - 1) if length > 1 else b""
        if payload is None:
            out.put(None)
            return
        out.put((kind, payload))


def check(result, version, libradicle):
    problems = []
    if result.get("protocol") != 1:
        problems.append(f"protocol {result.get('protocol')!r}, not 1")
    if result.get("service_version") != version:
        problems.append(f"service_version {result.get('service_version')!r}, not {version!r}")
    if result.get("libradicle") != libradicle:
        problems.append(f"libradicle {result.get('libradicle')!r}, not {libradicle!r}")
    try:
        recipient = base64.b64decode(result.get("recipient") or "", validate=True)
    except ValueError:
        recipient = b""
    if len(recipient) != 32:
        problems.append(f"recipient {result.get('recipient')!r} isn't 32 bytes of base64")
    if result.get("network") != {"mode": "direct"}:
        problems.append(f"network {result.get('network')!r}, not direct")
    if not isinstance(result.get("confinement"), dict):
        problems.append(f"confinement {result.get('confinement')!r} isn't an object")
    if problems:
        raise HelloError("rad.hello's reply: " + "; ".join(problems))


def hello(binary):
    version, libradicle = expected()
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        own_home = root / "radicled-home"
        own_home.mkdir()
        env = {"HOME": str(own_home)}
        if os.name == "nt" and "SystemRoot" in os.environ:
            env["SystemRoot"] = os.environ["SystemRoot"]
        argv = [
            str(binary), "serve",
            "--home", str(root / "R" / "1"),
            "--lock-dir", str(root / "locks"),
            "--network", "direct",
        ]
        # stderr, the service's log, goes to the job's log. close_fds (the
        # default): the service sees no descriptor but its stdio.
        child = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        frames = queue.Queue()
        threading.Thread(target=read_frames, args=(child.stdout, frames), daemon=True).start()
        try:
            child.stdin.write(frame({
                "type": "request", "id": 1, "method": "rad.hello",
                "params": {"protocol": 1, "shell_version": "release-smoke", "frames": ["stream"]},
            }))
            child.stdin.flush()
            while True:
                try:
                    item = frames.get(timeout=REPLY_TIMEOUT)
                except queue.Empty:
                    raise HelloError(f"no reply to rad.hello within {REPLY_TIMEOUT} s") from None
                if item is None:
                    raise HelloError(f"stdout ended before rad.hello's reply (exit {child.wait()})")
                kind, payload = item
                if kind != KIND_JSON:
                    raise HelloError(f"a frame of kind {kind:#04x} before rad.hello's reply")
                message = json.loads(payload)
                if message.get("id") == 1:
                    break
            print("rad.hello:", json.dumps(message, indent=2, sort_keys=True), flush=True)
            if not isinstance(message.get("result"), dict):
                raise HelloError(f"rad.hello failed: {message.get('error')!r}")
            check(message["result"], version, libradicle)
            child.stdin.close()
            try:
                code = child.wait(timeout=EXIT_TIMEOUT)
            except subprocess.TimeoutExpired:
                raise HelloError(f"still running {EXIT_TIMEOUT} s after stdin closed") from None
            if code != 0:
                raise HelloError(f"exit {code} after stdin closed, not 0")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
    print(f"rad.hello: {binary} answered as freedom-radicled {version}, "
          f"libradicle {libradicle['version']} at {libradicle['git_commit']}, and exited 0",
          flush=True)


def main():
    if len(sys.argv) != 2:
        print("usage: radicled-hello.py <binary>", file=sys.stderr)
        return 64
    try:
        hello(pathlib.Path(sys.argv[1]).resolve())
    except (HelloError, OSError) as e:
        print(f"radicled-hello: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
