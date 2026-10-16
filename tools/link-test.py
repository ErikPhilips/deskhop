#!/usr/bin/env python3
"""Talk to the box over the DeskHop Link from the PC (protocol.md, Test vectors and test tool).

    pip install -r tools/requirements-link.txt hidapi
    python tools/link-test.py list
    python tools/link-test.py status
    python tools/link-test.py read [--out blob.bin]

This firmware answers only the open, read-only messages (STATUS, Get configuration).
Pairing, sessions, edge hits and uploads come later.
"""

import argparse
import os
import secrets
import struct
import sys
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import deskhop_link as dl  # noqa: E402

try:
    import hid
except ImportError:
    sys.exit("needs hidapi: pip install hidapi")

VID, PID = 0x1209, 0xC000
USAGE_PAGE, USAGE = 0xFF00, 0x30

BOARD_TYPES = {1: "rp2040", 2: "rt1062"}
BOX_STATES = {0: "idle", 1: "challenge pending", 2: "upload open"}
HELLO_OS = {0: "never", 1: "Windows", 2: "macOS", 3: "Linux"}


def link_interfaces():
    return [d for d in hid.enumerate(VID, PID)
            if d.get("usage_page") == USAGE_PAGE and d.get("usage") == USAGE]


class Link:
    def __init__(self, path):
        self.dev = hid.device()
        self.dev.open_path(path)
        self.rx = dl.Reassembler()
        # Drop anything stale (HidD_FlushQueue's job in the app).
        # Non-blocking for the flush: in cython-hidapi, read(n, 0) blocks forever.
        self.dev.set_nonblocking(1)
        while self.dev.read(dl.REPORT_SIZE):
            pass
        self.dev.set_nonblocking(0)

    def close(self):
        self.dev.close()

    def send(self, type_, body):
        for report in dl.split_reports(dl.encode_frame(type_, body)):
            # Report ID 0 first: the interface has no report IDs
            self.dev.write(b"\x00" + report)

    def frames(self, timeout):
        """Yield (type, body) for each frame that arrives before the deadline."""
        deadline = time.monotonic() + timeout
        while True:
            left_ms = int((deadline - time.monotonic()) * 1000)
            if left_ms <= 0:
                return
            data = self.dev.read(dl.REPORT_SIZE, left_ms)
            if not data:
                continue
            report = bytes(data)
            # Some hidapi backends hand back the report ID byte too
            if len(report) == dl.REPORT_SIZE + 1:
                report = report[1:]
            frame = self.rx.feed(report.ljust(dl.REPORT_SIZE, b"\0")[:dl.REPORT_SIZE])
            if frame is not None:
                type_, _ = dl.parse_header(frame)
                yield type_, frame[dl.HEADER_SIZE:]


def open_link(args):
    found = link_interfaces()
    if not found:
        sys.exit("No DeskHop Link interface found (1209:c000, usage page 0xFF00, usage 0x30). "
                 "Is the new firmware on the board this PC is cabled to?")
    return Link(found[0]["path"])


def cmd_list(args):
    found = link_interfaces()
    if not found:
        print("none")
    for d in found:
        print("%s  interface %s  %s" % (d["product_string"], d["interface_number"],
                                        d["path"].decode(errors="replace")))
    return 0 if found else 1


def cmd_status(args):
    link = open_link(args)
    corr = secrets.randbits(32)
    try:
        link.send(dl.STATUS_GET, dl.encode_body(dl.STATUS_GET, {"corr": corr}))
        for type_, body in link.frames(args.timeout):
            if type_ != dl.STATUS:
                continue
            s = dl.decode_body(dl.STATUS, body)
            if s["corr"] != corr:
                continue
            print_status(s)
            return 0
    finally:
        link.close()
    print("no STATUS within %.1f s" % args.timeout)
    return 1


def print_status(s):
    print("proto          %d" % s["proto"])
    print("fw_tag         %s" % s["fw_tag"])
    print("schema         %d" % s["schema"])
    print("board_type     %d (%s)" % (s["board_type"], BOARD_TYPES.get(s["board_type"], "?")))
    print("computer       %s" % ("AB"[s["computer"]] if s["computer"] < 2 else s["computer"]))
    print("paired         %d" % s["paired"])
    print("box_state      %d (%s)" % (s["box_state"], BOX_STATES.get(s["box_state"], "?")))
    print("limits         profiles %d, rules %d, name %d, blob %d"
          % (s["max_profiles"], s["max_rules"], s["max_name"], s["max_blob"]))
    print("os_a / os_b    %s / %s" % (HELLO_OS.get(s["os_a"], s["os_a"]), HELLO_OS.get(s["os_b"], s["os_b"])))
    print("ss_hash a / b  %08x / %08x" % (s["ss_hash_a"], s["ss_hash_b"]))
    print("devices        %d" % len(s["devices"]))
    for d in s["devices"]:
        print("  board %s  %04x:%04x  poll %d us  %s"
              % ("AB"[d["board"]] if d["board"] < 2 else d["board"], d["vid"], d["pid"],
                 d["poll_us"], d["name"] or "(no name)"))


def cmd_read(args):
    link = open_link(args)
    corr = secrets.randbits(32)
    begin = None
    blob = bytearray()
    try:
        link.send(dl.READ_REQUEST, dl.encode_body(dl.READ_REQUEST, {"corr": corr}))
        for type_, body in link.frames(args.timeout):
            if type_ == dl.READ_BEGIN:
                f = dl.decode_body(type_, body)
                if f["corr"] != corr:
                    continue
                if f["status"] != 0:
                    print("READ_BEGIN status %d (busy)" % f["status"])
                    return 1
                begin = f
                if f["total_len"] == 0:
                    break
            elif type_ == dl.READ_DATA and begin is not None:
                f = dl.decode_body(type_, body)
                if f["corr"] != corr:
                    continue
                if f["offset"] != len(blob):
                    print("gap: expected offset %d, got %d" % (len(blob), f["offset"]))
                    return 1
                blob += f["data"]
                if f["offset"] + len(f["data"]) == begin["total_len"]:
                    break
    finally:
        link.close()

    if begin is None:
        print("no READ_BEGIN within %.1f s" % args.timeout)
        return 1
    if len(blob) != begin["total_len"]:
        print("incomplete: %d of %d bytes" % (len(blob), begin["total_len"]))
        return 1

    crc = zlib.crc32(blob)
    print("blob           %d bytes, schema %d" % (len(blob), begin["schema"]))
    print("crc32          %08x (box) %08x (computed) %s"
          % (begin["crc32"], crc, "OK" if crc == begin["crc32"] else "MISMATCH"))
    if args.out:
        with open(args.out, "wb") as f:
            f.write(blob)
        print("saved          %s" % args.out)
    if begin["schema"] == 8 and len(blob) == CONFIG_V8_SIZE:
        print_config_v8(bytes(blob))
    return 0 if crc == begin["crc32"] else 1


# rp2040 config_t, CURRENT_CONFIG_VERSION 8, ARM EABI layout (src/include/structs.h, screen.h).
# Only used to print a few fields as a sanity check; the real blob format comes with the settings rework.
CONFIG_V8_SIZE = 136
OUTPUT_V8 = struct.Struct("<IIIii ii BBB x BB 6x QQ")   # 56 bytes
OS_NAMES = {1: "Linux", 2: "macOS", 3: "Windows", 4: "Android", 255: "other"}
POS_NAMES = {0: "none", 1: "left", 2: "right", 3: "middle"}


def print_config_v8(blob):
    magic, version = struct.unpack_from("<II", blob, 0)
    jump_threshold = struct.unpack_from("<H", blob, 14)[0]
    gaming_default, led_mode = blob[128], blob[129]
    stored_crc = struct.unpack_from("<I", blob, 132)[0]
    print("config         magic %08x, version %d, jump_threshold %d, gaming_mode_default %d, led_mode %d"
          % (magic, version, jump_threshold, gaming_default, led_mode))
    for i in range(2):
        (number, screens, _index, speed_x, speed_y, top, bottom, os_, pos, park,
         ss_mode, ss_inactive, ss_idle, ss_max) = OUTPUT_V8.unpack_from(blob, 16 + 56 * i)
        print("output %s       os %s, pos %s, screens %d, speed %d/%d, screensaver mode %d"
              % ("AB"[i], OS_NAMES.get(os_, os_), POS_NAMES.get(pos, pos), screens, speed_x, speed_y, ss_mode))
    same = zlib.crc32(blob[:132]) == stored_crc
    print("config crc     %s" % ("matches the stored checksum" if same
                                 else "differs from the stored checksum (settings changed since the last save)"))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--timeout", type=float, default=2.0, help="seconds to wait for replies")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list DeskHop Link interfaces")
    sub.add_parser("status", help="STATUS_GET and print the reply")
    r = sub.add_parser("read", help="Get configuration and verify the CRC")
    r.add_argument("--out", help="save the blob to this file")
    args = ap.parse_args()
    return {"list": cmd_list, "status": cmd_status, "read": cmd_read}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
