#!/usr/bin/env python3
"""Run the firmware's link codec (src/link_codec.c, built by tests/link) against test-vectors/link/.

    cmake -S tests/link -B build-host
    cmake --build build-host
    ctest --test-dir build-host -C Debug --output-on-failure

or directly: python tools/run-link-codec-tests.py <path to test_link_codec executable>

The JSON vectors are flattened into the line script test_link_codec.c reads on stdin.
"""

import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTORS = os.path.join(REPO, "test-vectors", "link")

# link_band_t values in src/include/link_codec.h
BAND = {None: 0, (False, "priority"): 1, (True, "priority"): 2, (True, "bulk"): 3, (False, "bulk"): 4}


def load(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as f:
        return json.load(f)


def script():
    framing = load("framing.json")
    messages = load("messages.json")
    out = []

    for case in framing["decode"]:
        out.append("case " + case["name"])
        out += ["feed " + r for r in case["reports"]]
        out += ["expect " + f for f in case["frames"]]
        out.append("end")

    encodes = [(c["frame"], c["reports"]) for c in framing["encode"]]
    encodes += [(m["frame"], m["reports"]) for m in messages["messages"]]
    for frame, reports in encodes:
        out.append("encode " + frame)
        out += ["report " + r for r in reports]
        out.append("endencode")

    for t in range(256):
        band = None
        for b in framing["bands"]:
            if int(b["first"], 16) <= t <= int(b["last"], 16):
                band = (b["signed"], b["queue"])
        out.append("band %02x %d" % (t, BAND[band]))

    for m in messages["messages"]:
        f = m["fields"]
        if m["name"] in ("STATUS_GET", "READ_REQUEST"):
            out.append("corr %s 1 %d" % (m["body"], f["corr"]))
        elif m["name"] == "STATUS":
            tag = f["fw_tag"].encode("ascii").ljust(16, b"\0").hex()
            out.append("status " + " ".join(str(x) for x in [
                f["corr"], f["proto"], tag, f["schema"], f["board_type"], f["computer"],
                f["paired"], f["box_state"], f["max_profiles"], f["max_rules"], f["max_name"],
                f["max_blob"], f["os_a"], f["os_b"], f["ss_hash_a"], f["ss_hash_b"]]))
            for d in f["devices"]:
                name = d["name"].encode("utf-8").hex() or "-"
                out.append("device %d %d %d %d %s" % (d["board"], d["vid"], d["pid"], d["poll_us"], name))
            out.append("expectbody " + m["body"])
        elif m["name"] == "READ_BEGIN":
            out.append("read_begin %d %d %d %d %d" % (f["corr"], f["status"], f["total_len"],
                                                      f["crc32"], f["schema"]))
            out.append("expectbody " + m["body"])
        elif m["name"] == "READ_DATA":
            out.append("read_data %d %d %s" % (f["corr"], f["offset"], f["data"] or "-"))
            out.append("expectbody " + m["body"])

    for bad in messages["malformed"]:
        if bad["type_name"] in ("STATUS_GET", "READ_REQUEST"):
            out.append("corr %s 0 0" % (bad["body"] or "-"))
    out += ["corr - 0 0", "corr 0102030405 0 0"]

    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    r = subprocess.run([sys.argv[1]], input=script(), text=True, capture_output=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
