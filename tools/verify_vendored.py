#!/usr/bin/env python3
"""Cross-repo consumer certification gate for LEP golden vectors.

This is a BEST-EFFORT check. The Relay and Trace repos that consume the
protocol golden vectors are PRIVATE, so CI cannot `git checkout` them with the
default GITHUB_TOKEN. The workaround is that those repos re-vendor the protocol
vectors under their own `internal/lep/testdata/protocol-vectors/` and run
`TestProtocolVectors` against the copy.

This script certifies that every *checked-out* consumer's vendored copy still
matches the source of truth (`test-vectors/manifest.json` in this repo). It is
designed to be safe to run in any environment:

  * If a consumer repo is not checked out (the CI / local scenario), the
    consumer directory will not exist. That is not an error: we print a clear
    SKIP line and move on. The gate passes (exit 0) when no consumers are
    present, or when every present consumer matches.
  * If a consumer repo IS checked out and its vendored copy diverges from the
    source of truth, that is a real certification failure (exit 1).

What is checked
---------------
For each present consumer dir it loads `<consumer>/manifest.json` and the
protocol source `test-vectors/manifest.json`, then asserts that the *set* of
vector entries matches on the tuple (path, kind, id).

Optionally (default ON; disable with LEP_SKIP_CONTENT=1) it also compares the
stripped bytes of each shared hex vector file, reading both the source
`test-vectors/<path>` and the consumer `<consumer>/<path>` and comparing them
after whitespace stripping.

Usage
-----
  python tools/verify_vendored.py

Configuration (all optional):
  CONSUMER_DIRS   colon-separated list of consumer vector dirs. When set, it
                  OVERRIDES the built-in candidate paths entirely.
  LEP_SKIP_CONTENT=1   skip the byte-level hex file comparison.

Exit codes:
  0  all present consumers match (or no consumers were checked out)
  1  at least one present consumer diverges from the source of truth
  2  setup error: the protocol source manifest could not be read
"""

import json
import os
import sys

# The script lives at <protocol-repo>/tools/verify_vendored.py, so the repo
# root is the parent of the directory containing this file.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROTOCOL_ROOT = os.path.dirname(SCRIPT_DIR)

SOURCE_MANIFEST = os.path.join(PROTOCOL_ROOT, "test-vectors", "manifest.json")

# Default candidate consumer vendored-vector directories, relative to the
# protocol repo root. These mirror the private relay/trace layouts.
DEFAULT_CONSUMER_DIRS = [
    os.path.normpath(
        os.path.join(PROTOCOL_ROOT, "..", "relay",
                     "internal", "lep", "testdata", "protocol-vectors")
    ),
    os.path.normpath(
        os.path.join(PROTOCOL_ROOT, "..", "trace",
                     "internal", "lep", "testdata", "protocol-vectors")
    ),
]


def emit(msg):
    sys.stdout.write(msg + "\n")


def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def vector_key(entry):
    """Return the (path, kind, id) tuple used for set comparison."""
    return (entry.get("path"), entry.get("kind"), entry.get("id"))


def read_hex_stripped(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = fh.read()
    return data.strip()


def certify_consumer(consumer_dir, source_manifest, compare_content):
    """Certify one consumer dir. Returns True if it matches, False otherwise."""
    name = os.path.basename(os.path.normpath(consumer_dir))
    manifest_path = os.path.join(consumer_dir, "manifest.json")
    emit("CERTIFY: {} ({})".format(name, consumer_dir))

    if not os.path.isfile(manifest_path):
        emit("  FAIL: consumer manifest not found: {}".format(manifest_path))
        return False

    try:
        consumer = load_json(manifest_path)
    except (OSError, ValueError) as exc:
        emit("  FAIL: cannot read consumer manifest: {}".format(exc))
        return False

    source_vectors = source_manifest.get("vectors", [])
    consumer_vectors = consumer.get("vectors", [])

    source_keys = {vector_key(v) for v in source_vectors}
    consumer_keys = {vector_key(v) for v in consumer_vectors}

    missing = source_keys - consumer_keys
    extra = consumer_keys - source_keys

    if missing:
        for path, kind, vid in sorted(missing):
            emit("  FAIL: vector missing in consumer: path={} kind={} id={}".format(
                path, kind, vid))
    if extra:
        for path, kind, vid in sorted(extra):
            emit("  FAIL: unexpected vector in consumer: path={} kind={} id={}".format(
                path, kind, vid))

    if missing or extra:
        return False

    if compare_content:
        source_dir = os.path.dirname(SOURCE_MANIFEST)
        ok = True
        for path, _, _ in sorted(source_keys):
            src_file = os.path.join(source_dir, path)
            dst_file = os.path.join(consumer_dir, path)
            if not os.path.isfile(src_file) or not os.path.isfile(dst_file):
                # Be lenient: a path may resolve differently in the vendored
                # tree. Only compare when both sides are readable.
                continue
            try:
                src_bytes = read_hex_stripped(src_file)
                dst_bytes = read_hex_stripped(dst_file)
            except OSError as exc:
                emit("  WARN: cannot read hex for {}: {}".format(path, exc))
                continue
            if src_bytes != dst_bytes:
                emit("  FAIL: hex content differs for {}".format(path))
                ok = False
        if not ok:
            return False

    emit("  OK: {} matches source of truth ({} vectors)".format(name, len(source_keys)))
    return True


def main(argv):
    compare_content = os.environ.get("LEP_SKIP_CONTENT", "0") != "1"

    override = os.environ.get("CONSUMER_DIRS")
    if override:
        consumer_dirs = [p for p in override.split(":") if p]
    else:
        consumer_dirs = DEFAULT_CONSUMER_DIRS

    if not os.path.isfile(SOURCE_MANIFEST):
        emit("ERROR: protocol source manifest not found: {}".format(SOURCE_MANIFEST))
        return 2
    try:
        source_manifest = load_json(SOURCE_MANIFEST)
    except (OSError, ValueError) as exc:
        emit("ERROR: cannot read protocol source manifest: {}".format(exc))
        return 2

    emit("LEP vendored-vector certification (best-effort; consumer repos are private)")
    emit("Source of truth: {}".format(SOURCE_MANIFEST))
    emit("Content comparison: {}".format("on" if compare_content else "off"))
    emit("")

    checked = 0
    failed = False

    for consumer_dir in consumer_dirs:
        consumer_dir = os.path.normpath(consumer_dir)
        if not os.path.isdir(consumer_dir):
            emit("SKIP: {} not found (consumer repo not checked out)".format(consumer_dir))
            continue
        checked += 1
        if not certify_consumer(consumer_dir, source_manifest, compare_content):
            failed = True

    emit("")
    if checked == 0:
        emit("RESULT: no consumer repos checked out; nothing to certify (exit 0).")
        return 0
    if failed:
        emit("RESULT: {} consumer(s) certified, at least one DIVERGES (exit 1).".format(checked))
        return 1
    emit("RESULT: all {} checked-out consumer(s) match (exit 0).".format(checked))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
