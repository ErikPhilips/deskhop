#!/usr/bin/env python3
"""Write test-vectors/link/ from the reference module (tools/deskhop_link.py).

    python tools/gen-link-vectors.py            # (re)write the vectors
    python tools/gen-link-vectors.py --check    # exit 1 if the files on disk differ

Every input is fixed (key pairs from hashed labels, literal nonces, codes and IDs), so the
output is deterministic. The firmware, the Windows app and the Swift app must reproduce
these files byte for byte; see test-vectors/link/README.md for the layout.
"""

import argparse
import hashlib
import json
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import deskhop_link as dl  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(REPO, "test-vectors", "link")

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
MAX_SAFE_INT = 2 ** 53 - 1      # largest counter used, so JSON readers on doubles stay exact


def hx(b):
    return bytes(b).hex()


def label_bytes(label, n):
    """n deterministic bytes from a label (SHA-256 in counter mode)."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(("deskhop-link test " + label).encode() + bytes([i])).digest()
        i += 1
    return out[:n]


def test_private_key(label):
    d = label_bytes(label, 32)
    assert 1 <= int.from_bytes(d, "big") < P256_N
    return dl.private_key_from_scalar(d)


def jsonable(v):
    if isinstance(v, (bytes, bytearray)):
        return hx(v)
    if isinstance(v, dict):
        return {k: jsonable(x) for k, x in v.items()}
    if isinstance(v, list):
        return [jsonable(x) for x in v]
    return v


def frame_record(frame):
    return {"frame": hx(frame), "reports": [hx(r) for r in dl.split_reports(frame)]}


def message_record(type_, fields, key_name=None, key=None, counter=None):
    body = dl.encode_body(type_, fields)
    rec = {
        "name": dl.NAMES[type_],
        "type": "0x%02x" % type_,
        "dir": dl.DIRECTION[type_],
        "signed": dl.is_signed(type_),
        "fields": jsonable(fields),
        "body": hx(body),
    }
    if dl.is_signed(type_):
        frame = dl.encode_signed_frame(type_, key, counter, body)
        rec["key"] = key_name
        rec["counter"] = counter
        rec["tag"] = hx(frame[dl.HEADER_SIZE + dl.COUNTER_SIZE:dl.HEADER_SIZE + dl.AUTH_SIZE])
    else:
        frame = dl.encode_frame(type_, body)
    rec.update(frame_record(frame))
    return rec


# ---------------------------------------------------------------------------
# Fixed inputs

HELPER_1 = test_private_key("helper key 1")
BOARD_1 = test_private_key("board key 1")
HELPER_2 = test_private_key("helper key 2")
BOARD_2 = test_private_key("board key 2")

HELPER_NONCE_1 = label_bytes("helper nonce 1", 16)
BOARD_NONCE_1 = label_bytes("board nonce 1", 16)
HELPER_NONCE_2 = label_bytes("helper nonce 2", 16)
BOARD_NONCE_2 = label_bytes("board nonce 2", 16)

CODES_1 = ["KDHP", "WXRT", "ZBMA"]      # attempts 1-3 for pairing set 1
CODES_2 = ["QEFG", "NUVY", "CJSK"]

READ_BLOB = label_bytes("read blob", 600)
UPLOAD_BLOB = label_bytes("upload blob", 700)


def pairing_set(helper, board, codes):
    hp, bp = dl.public_bytes(helper), dl.public_bytes(board)
    keys = dl.pairing_keys(helper, hp, bp, bp)
    attempts = []
    for n, letters in enumerate(codes, start=1):
        code = dl.code_from_letters(letters)
        pad = keys.pad(n)
        attempts.append({"attempt": n, "pad": hx(pad), "code": hx(code), "letters": letters,
                         "code_ct": hx(dl.xor_code(code, pad))})
    return {
        "helper_priv": hx(dl.private_scalar(helper)),
        "helper_pub": hx(hp),
        "board_priv": hx(dl.private_scalar(board)),
        "board_pub": hx(bp),
        "ss": hx(keys.ss),
        "th": hx(keys.th),
        "k_pair_prk": hx(dl.hkdf_extract(keys.th, keys.ss)),
        "k_pair": hx(keys.k_pair),
        "key_id": hx(keys.key_id),
        "attempts": attempts,
    }, keys


def session_set(name, k_pair, helper_nonce, board_nonce):
    k_h2b, k_b2h = dl.derive_session_keys(k_pair, helper_nonce, board_nonce)
    return {
        "name": name,
        "k_pair": hx(k_pair),
        "helper_nonce": hx(helper_nonce),
        "board_nonce": hx(board_nonce),
        "salt": hx(helper_nonce + board_nonce),
        "k_h2b": hx(k_h2b),
        "k_b2h": hx(k_b2h),
    }, (k_h2b, k_b2h)


PAIR_1, KEYS_1 = pairing_set(HELPER_1, BOARD_1, CODES_1)
PAIR_2, KEYS_2 = pairing_set(HELPER_2, BOARD_2, CODES_2)
SESSION_A, (H2B_A, B2H_A) = session_set("A", KEYS_1.k_pair, HELPER_NONCE_1, BOARD_NONCE_1)
SESSION_B, (H2B_B, B2H_B) = session_set("B", KEYS_1.k_pair, HELPER_NONCE_2, BOARD_NONCE_2)
SESSION_C, _ = session_set("C", KEYS_2.k_pair, HELPER_NONCE_1, BOARD_NONCE_1)

STATUS_FIELDS = {
    "corr": 0x7A1C0E01, "proto": dl.PROTO_VERSION, "fw_tag": "0.78-1f45232", "schema": 1,
    "board_type": 1, "computer": 0, "paired": 0, "box_state": 0, "max_profiles": 8,
    "max_rules": 32, "max_name": 24, "max_blob": 8192, "os_a": 0, "os_b": 1,
    "ss_hash_a": 0x1234ABCD, "ss_hash_b": 0x1234ABCD,
    "devices": [
        {"board": 0, "vid": 0x1D57, "pid": 0xFA60, "poll_us": 125, "name": "Test Mouse"},
        {"board": 1, "vid": 0x04D9, "pid": 0xA0F8, "poll_us": 1000, "name": "Test Keyboard Ä"},
    ],
}


# ---------------------------------------------------------------------------
# framing.json

def pattern(n, seed=0):
    return bytes(((i * 37 + seed) % 255) + 1 for i in range(n))


def build_framing():
    encode = []
    for name, type_, n in [
        ("empty body", 0x01, 0),
        ("4-byte body, one report", 0x01, 4),
        ("60-byte body fills one report exactly", 0x02, 60),
        ("61-byte body spills one byte into a second report", 0x02, 61),
        ("123-byte body fills two reports exactly", 0x42, 123),
        ("max len 1024, 17 reports", 0x42, 1024),
    ]:
        frame = dl.encode_frame(type_, pattern(n, type_))
        encode.append(dict({"name": name}, **frame_record(frame)))

    fa = dl.encode_frame(0x41, pattern(100, 1))
    fb = dl.encode_frame(0x02, pattern(10, 2))
    fc = dl.encode_frame(0x42, pattern(150, 3))
    a, b, c = dl.split_reports(fa), dl.split_reports(fb), dl.split_reports(fc)   # 2, 1, 3 reports
    zero = bytes(dl.REPORT_SIZE)

    def with_tail(report, at):
        r = bytearray(report)
        r[at] = 0xEE
        return bytes(r)

    b_dirty = with_tail(b[0], 1 + dl.HEADER_SIZE + 10)              # byte right after the frame
    a_dirty = a[:1] + [with_tail(a[1], 63)]                          # last byte of the last report
    type0 = bytes([dl.FLAG_START, 0x00, 5, 0]) + pattern(5) + bytes(dl.REPORT_SIZE - 9)
    too_long_frame = bytes([0x42]) + (dl.MAX_LEN + 1).to_bytes(2, "little") + pattern(dl.MAX_LEN + 1)
    too_long = dl.split_reports(too_long_frame)
    max_frame = dl.encode_frame(0x42, pattern(dl.MAX_LEN, 9))

    decode = [
        ("single-report frame", b, [fb]),
        ("frames back to back", a + b + c, [fa, fb, fc]),
        ("idle all-zero report is dropped", [zero] + b + [zero], [fb]),
        ("lost head: continuation reports with no frame in progress are dropped", a[1:] + c[1:] + b, [fb]),
        ("lost last report: the next start drops the frame in progress", a[:1] + b, [fb]),
        ("lost middle report: the frame never completes and the next start drops it",
         [c[0], c[2]] + b, [fb]),
        ("multi-report frame interrupted by another multi-report frame", c[:2] + a, [fa]),
        ("non-padding byte after a frame that ends mid-report drops the frame", [b_dirty] + b, [fb]),
        ("non-padding byte in the last report of a multi-report frame drops the frame",
         a_dirty + b, [fb]),
        ("start flag with type 0x00 is dropped", [type0] + b, [fb]),
        ("len 1025 is malformed; its continuation reports are then orphans", too_long + b, [fb]),
        ("len 1024 is accepted", dl.split_reports(max_frame), [max_frame]),
    ]

    types = []
    for t in sorted(dl.NAMES):
        bd = dl.band(t)
        types.append({"type": "0x%02x" % t, "name": dl.NAMES[t], "dir": dl.DIRECTION[t],
                      "signed": bd.signed, "queue": bd.queue})

    return {
        "about": "Report splitting and resync. Bodies are byte patterns, not valid messages: "
                 "the frame codec doesn't look past the header.",
        "report_size": dl.REPORT_SIZE,
        "max_len": dl.MAX_LEN,
        "encode": encode,
        "decode": [{"name": n, "reports": [hx(r) for r in rs], "frames": [hx(f) for f in fs]}
                   for n, rs, fs in decode],
        "bands": [{"first": "0x%02x" % b.first, "last": "0x%02x" % b.last, "signed": b.signed,
                   "queue": b.queue, "holds": b.holds} for b in dl.BANDS],
        "dropped_types": ["0x00", "0x50-0xff"],
        "types": types,
    }


# ---------------------------------------------------------------------------
# kdf.json

def build_kdf():
    return {
        "about": "P-256 ECDH and HKDF-SHA256 derivations. Pairing set 1 and sessions A and B "
                 "are the ones transcript.json and messages.json use.",
        "labels": {
            "pair": dl.INFO_PAIR.decode(), "code": dl.INFO_CODE.decode() + " || attempt u8",
            "id": dl.INFO_ID.decode(), "h2b": dl.INFO_H2B.decode(), "b2h": dl.INFO_B2H.decode(),
        },
        "pairing": [dict({"name": "1"}, **PAIR_1), dict({"name": "2"}, **PAIR_2)],
        "session": [SESSION_A, SESSION_B, SESSION_C],
    }


# ---------------------------------------------------------------------------
# messages.json

def build_messages():
    k = {"k_h2b": H2B_A, "k_b2h": B2H_A}

    def signed(type_, fields, counter):
        key_name = "k_h2b" if dl.DIRECTION[type_] == dl.H2B else "k_b2h"
        return message_record(type_, fields, key_name, k[key_name], counter)

    status_empty = dict(STATUS_FIELDS, corr=0x01020304, computer=1, paired=1, box_state=2,
                        os_a=1, os_b=2, devices=[])
    msgs = [
        message_record(dl.STATUS_GET, {"corr": 0x7A1C0E01}),
        message_record(dl.STATUS, STATUS_FIELDS),
        message_record(dl.STATUS, status_empty),
        message_record(dl.PAIR_REQUEST, {"corr": 0x7A1C0E03, "helper_pub": dl.public_bytes(HELPER_1)}),
        message_record(dl.PAIR_CHALLENGE, {
            "corr": 0x7A1C0E03, "board_pub": dl.public_bytes(BOARD_1), "attempt": 1,
            "code_ct": bytes.fromhex(PAIR_1["attempts"][0]["code_ct"])}),
        message_record(dl.PAIR_RESULT, {"corr": 0x7A1C0E03, "result": 0, "key_id": KEYS_1.key_id}),
        message_record(dl.PAIR_RESULT, {"corr": 0x7A1C0E03, "result": 2, "key_id": bytes(8)}),
        message_record(dl.HELLO, {
            "corr": 0x7A1C0E04, "proto": dl.PROTO_VERSION, "os": 1, "app_version": 0x0100,
            "key_id": KEYS_1.key_id, "helper_nonce": HELPER_NONCE_1}),
        message_record(dl.HELLO_REFUSED, {"corr": 0x7A1C0E04, "reason": 1}),
        signed(dl.HELLO_ACK, {"corr": 0x7A1C0E04, "proto": dl.PROTO_VERSION,
                              "board_nonce": BOARD_NONCE_1, "computer": 0, "board_type": 1,
                              "layout": 1}, 0),
        signed(dl.HEARTBEAT, {}, 0),
        signed(dl.HEARTBEAT, {}, MAX_SAFE_INT),
        signed(dl.STATE, {"active": 1, "layout": 0, "profile": 3, "box_state": 0}, 0x0011223344556677),
        signed(dl.SESSION_END, {}, 41),
        signed(dl.EDGE_HIT, {"edge": 3, "pos": 0xBEEF}, 258),
        signed(dl.CURSOR_WARP, {"edge": 2, "pos": 0x0102}, 65536),
        signed(dl.UPLOAD_START, {"total_len": len(UPLOAD_BLOB), "crc32": zlib.crc32(UPLOAD_BLOB),
                                 "schema": 1}, 7),
        signed(dl.UPLOAD_READY, {"upload_id": 0x5A17C0DE, "max_chunk": 512}, 8),
        signed(dl.UPLOAD_DATA, {"upload_id": 0x5A17C0DE, "offset": 0, "data": UPLOAD_BLOB[:512]}, 9),
        signed(dl.UPLOAD_DATA, {"upload_id": 0x5A17C0DE, "offset": 512, "data": UPLOAD_BLOB[512:]}, 10),
        signed(dl.UPLOAD_ABORT, {"upload_id": 0x5A17C0DE}, 11),
        signed(dl.UPLOAD_RESULT, {"upload_id": 0x5A17C0DE, "status": 0, "detail": 0}, 12),
        signed(dl.UPLOAD_RESULT, {"upload_id": 0, "status": 5, "detail": 0x0203}, 13),
        message_record(dl.READ_REQUEST, {"corr": 0x7A1C0E02}),
        message_record(dl.READ_BEGIN, {"corr": 0x7A1C0E02, "status": 0, "total_len": len(READ_BLOB),
                                       "crc32": zlib.crc32(READ_BLOB), "schema": 1}),
        message_record(dl.READ_DATA, {"corr": 0x7A1C0E02, "offset": 0, "data": READ_BLOB[:512]}),
        message_record(dl.READ_DATA, {"corr": 0x7A1C0E02, "offset": 512, "data": READ_BLOB[512:]}),
    ]
    return {
        "about": "One or more vectors per message type (FOREGROUND_APP 0x22 is reserved and has "
                 "no body yet). Signed ones use session A's keys and the counter given.",
        "keys": {"session": "A", "k_h2b": hx(H2B_A), "k_b2h": hx(B2H_A)},
        "messages": msgs,
    }


# ---------------------------------------------------------------------------
# verify.json

def build_verify():
    def flip(frame, at):
        f = bytearray(frame)
        f[at] ^= 0x01
        return bytes(f)

    tag_at = dl.HEADER_SIZE + dl.COUNTER_SIZE
    msg_at = dl.HEADER_SIZE + dl.AUTH_SIZE
    edge = dl.encode_body(dl.EDGE_HIT, {"edge": 1, "pos": 0x8000})
    warp = dl.encode_body(dl.CURSOR_WARP, {"edge": 0, "pos": 0x8000})
    state = dl.encode_body(dl.STATE, {"active": 0, "layout": 1, "profile": 0, "box_state": 0})
    ack = dl.encode_body(dl.HELLO_ACK, {"corr": 0x7A1C0E04, "proto": dl.PROTO_VERSION,
                                        "board_nonce": BOARD_NONCE_1, "computer": 0,
                                        "board_type": 1, "layout": 1})
    hb = lambda key, n: dl.encode_signed_frame(dl.HEARTBEAT, key, n, b"")  # noqa: E731
    short = dl.encode_frame(dl.HEARTBEAT, bytes(10))

    box_steps = [
        ("first frame of a session, counter 0", hb(H2B_A, 0), "accept"),
        ("replay of the same frame", hb(H2B_A, 0), "drop"),
        ("gap ahead is accepted", dl.encode_signed_frame(dl.EDGE_HIT, H2B_A, 5, edge), "accept"),
        ("older counter", hb(H2B_A, 3), "drop"),
        ("equal counter", hb(H2B_A, 5), "drop"),
        ("counter 100 with a bad tag: dropped and not recorded",
         flip(dl.encode_signed_frame(dl.EDGE_HIT, H2B_A, 100, edge), tag_at), "drop"),
        ("counter 6 is still newer than the last accepted (5)", hb(H2B_A, 6), "accept"),
        ("message body altered after signing",
         flip(dl.encode_signed_frame(dl.EDGE_HIT, H2B_A, 7, edge), msg_at + 2), "drop"),
        ("counter altered after signing", flip(hb(H2B_A, 7), dl.HEADER_SIZE), "drop"),
        ("signed with the other direction's key", hb(B2H_A, 7), "drop"),
        ("box-to-host type with a valid h2b tag",
         dl.encode_signed_frame(dl.CURSOR_WARP, H2B_A, 7, warp), "drop"),
        ("signed type with len 10, shorter than the auth prefix", short, "drop"),
        ("largest counter in the vectors", hb(H2B_A, MAX_SAFE_INT), "accept"),
    ]
    app_steps = [
        ("HELLO_ACK at counter 0", dl.encode_signed_frame(dl.HELLO_ACK, B2H_A, 0, ack), "accept"),
        ("STATE at counter 1", dl.encode_signed_frame(dl.STATE, B2H_A, 1, state), "accept"),
        ("replayed STATE", dl.encode_signed_frame(dl.STATE, B2H_A, 1, state), "drop"),
        ("host-to-box type with a valid b2h tag",
         dl.encode_signed_frame(dl.EDGE_HIT, B2H_A, 2, edge), "drop"),
        ("STATE from another session (same k_pair, other nonces)",
         dl.encode_signed_frame(dl.STATE, B2H_B, 2, state), "drop"),
        ("STATE at counter 2", dl.encode_signed_frame(dl.STATE, B2H_A, 2, state), "accept"),
    ]

    def run(role, key, steps):
        rx = dl.Receiver(role, key)
        out = []
        for note, frame, expect in steps:
            r = rx.accept(frame)
            assert (r is not None) == (expect == "accept"), note
            step = {"note": note, "frame": hx(frame), "expect": expect}
            if r is not None:
                step["counter"], step["message"] = r[0], hx(r[1])
            else:
                step["why"] = rx.last_drop
            step["highest_after"] = rx.highest
            out.append(step)
        return out

    # Pending session: A is confirmed (last accepted counter 4), B was just offered by HELLO_ACK.
    slot = dl.BoxSessionSlot()
    slot.confirmed = dl.Receiver("box", H2B_A)
    slot.confirmed.highest = 4
    slot.set_pending(H2B_B)
    names = {H2B_A: "A", H2B_B: "B"}
    pending_steps = []
    for note, frame, expect in [
        ("old session still works while B is pending", hb(H2B_A, 5), "accept"),
        ("first frame under B confirms it", hb(H2B_B, 0), "accept"),
        ("A is gone once B is confirmed", hb(H2B_A, 6), "drop"),
        ("B carries on", dl.encode_signed_frame(dl.EDGE_HIT, H2B_B, 1, edge), "accept"),
    ]:
        r = slot.receive(frame)
        assert (r is not None) == (expect == "accept"), note
        step = {"note": note, "frame": hx(frame), "expect": expect}
        if r is not None:
            step["counter"], step["message"] = r[0], hx(r[1])
        else:
            step["why"] = slot.last_drop
        step["confirmed_after"] = names[slot.confirmed.key] if slot.confirmed else None
        step["pending_after"] = names[slot.pending.key] if slot.pending else None
        pending_steps.append(step)

    return {
        "about": "Receive-side rules for signed frames. Each scenario starts from the state given "
                 "and feeds the frames in order; every drop is silent on the wire. `why` is "
                 "informative only.",
        "scenarios": [
            {"name": "box receiver", "role": "box", "key": hx(H2B_A), "start_highest": None,
             "steps": run("box", H2B_A, box_steps)},
            {"name": "app receiver", "role": "app", "key": hx(B2H_A), "start_highest": None,
             "steps": run("app", B2H_A, app_steps)},
            {"name": "pending session on the box", "role": "box",
             "start": {"confirmed": {"session": "A", "k_h2b": hx(H2B_A), "highest": 4},
                       "pending": {"session": "B", "k_h2b": hx(H2B_B), "highest": None}},
             "steps": pending_steps},
        ],
    }


# ---------------------------------------------------------------------------
# transcript.json

def build_transcript():
    hp, bp = dl.public_bytes(HELPER_1), dl.public_bytes(BOARD_1)
    tx_app = dl.Sender(H2B_A)
    tx_box = dl.Sender(B2H_A)
    steps = []

    def add(type_, fields, note=""):
        if dl.is_signed(type_):
            sender = tx_app if dl.DIRECTION[type_] == dl.H2B else tx_box
            counter = sender.next_counter
            sender.next_counter += 1
            key_name = "k_h2b" if sender is tx_app else "k_b2h"
            rec = message_record(type_, fields, key_name, sender.key, counter)
        else:
            rec = message_record(type_, fields)
        steps.append(dict({"step": len(steps) + 1}, **rec, note=note))

    corr_status, corr_read, corr_pair, corr_hello = 0x7A1C0E01, 0x7A1C0E02, 0x7A1C0E03, 0x7A1C0E04
    upload_id = 0x5A17C0DE
    a1, a2 = PAIR_1["attempts"][0], PAIR_1["attempts"][1]

    add(dl.STATUS_GET, {"corr": corr_status})
    add(dl.STATUS, dict(STATUS_FIELDS, corr=corr_status), "not paired yet")
    add(dl.READ_REQUEST, {"corr": corr_read})
    add(dl.READ_BEGIN, {"corr": corr_read, "status": 0, "total_len": len(READ_BLOB),
                        "crc32": zlib.crc32(READ_BLOB), "schema": 1})
    add(dl.READ_DATA, {"corr": corr_read, "offset": 0, "data": READ_BLOB[:512]})
    add(dl.READ_DATA, {"corr": corr_read, "offset": 512, "data": READ_BLOB[512:]},
        "offset + data length = total_len: read complete")
    add(dl.PAIR_REQUEST, {"corr": corr_pair, "helper_pub": hp})
    add(dl.PAIR_CHALLENGE, {"corr": corr_pair, "board_pub": bp, "attempt": 1,
                            "code_ct": bytes.fromhex(a1["code_ct"])},
        "code %s; Erik types a wrong code" % a1["letters"])
    add(dl.PAIR_CHALLENGE, {"corr": corr_pair, "board_pub": bp, "attempt": 2,
                            "code_ct": bytes.fromhex(a2["code_ct"])},
        "same handshake, new code %s; Erik types it" % a2["letters"])
    add(dl.PAIR_RESULT, {"corr": corr_pair, "result": 0, "key_id": KEYS_1.key_id},
        "both sides store k_pair")
    add(dl.HELLO, {"corr": corr_hello, "proto": dl.PROTO_VERSION, "os": 1, "app_version": 0x0100,
                   "key_id": KEYS_1.key_id, "helper_nonce": HELPER_NONCE_1})
    add(dl.HELLO_ACK, {"corr": corr_hello, "proto": dl.PROTO_VERSION, "board_nonce": BOARD_NONCE_1,
                       "computer": 0, "board_type": 1, "layout": 1},
        "keys pending on the box")
    add(dl.HEARTBEAT, {}, "first app frame under the new keys: the box confirms the session")
    add(dl.STATE, {"active": 0, "layout": 1, "profile": 0, "box_state": 0}, "answer to HEARTBEAT")
    add(dl.EDGE_HIT, {"edge": 1, "pos": 0x8000}, "edge = layout: the box switches to B")
    add(dl.STATE, {"active": 1, "layout": 1, "profile": 0, "box_state": 0}, "unprompted: active changed")
    add(dl.CURSOR_WARP, {"edge": 1, "pos": 0x4000},
        "later, B's app hits B's left edge; A's board warps A's cursor to A's right edge")
    add(dl.STATE, {"active": 0, "layout": 1, "profile": 0, "box_state": 0}, "unprompted: active changed")
    add(dl.UPLOAD_START, {"total_len": len(UPLOAD_BLOB), "crc32": zlib.crc32(UPLOAD_BLOB), "schema": 1})
    add(dl.UPLOAD_READY, {"upload_id": upload_id, "max_chunk": 512})
    add(dl.UPLOAD_DATA, {"upload_id": upload_id, "offset": 0, "data": UPLOAD_BLOB[:512]})
    add(dl.UPLOAD_DATA, {"upload_id": upload_id, "offset": 512, "data": UPLOAD_BLOB[512:]})
    add(dl.UPLOAD_RESULT, {"upload_id": upload_id, "status": 0, "detail": 0}, "committed")
    add(dl.HEARTBEAT, {}, "1 s with nothing sent")
    add(dl.STATE, {"active": 0, "layout": 1, "profile": 0, "box_state": 0}, "answer to HEARTBEAT")
    add(dl.SESSION_END, {}, "app exiting")

    return {
        "about": "Status, Get configuration, pairing (one wrong code), session, edge crossing, "
                 "upload, heartbeat, session end, for one computer. Unprompted STATE frames "
                 "around the upload (box_state 2 and back) are left out.",
        "app": {"helper_priv": PAIR_1["helper_priv"], "helper_pub": hx(hp),
                "helper_nonce": hx(HELPER_NONCE_1)},
        "box": {"board_priv": PAIR_1["board_priv"], "board_pub": hx(bp),
                "codes": [a1["code"], a2["code"]], "board_nonce": hx(BOARD_NONCE_1),
                "upload_id": upload_id},
        "derived": {"ss": PAIR_1["ss"], "th": PAIR_1["th"], "k_pair": PAIR_1["k_pair"],
                    "key_id": PAIR_1["key_id"], "pads": [a1["pad"], a2["pad"]],
                    "k_h2b": hx(H2B_A), "k_b2h": hx(B2H_A)},
        "blobs": {"read": hx(READ_BLOB), "read_crc32": zlib.crc32(READ_BLOB),
                  "upload": hx(UPLOAD_BLOB), "upload_crc32": zlib.crc32(UPLOAD_BLOB)},
        "steps": steps,
    }


# ---------------------------------------------------------------------------

def build_all():
    return {
        "framing.json": build_framing(),
        "kdf.json": build_kdf(),
        "messages.json": build_messages(),
        "verify.json": build_verify(),
        "transcript.json": build_transcript(),
    }


def dump(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="compare with the files on disk")
    ap.add_argument("--out", default=OUT_DIR)
    args = ap.parse_args()

    stale = []
    for name, obj in build_all().items():
        path = os.path.join(args.out, name)
        if args.check:
            try:
                with open(path, encoding="utf-8") as f:
                    if json.load(f) != json.loads(dump(obj)):
                        stale.append(name)
            except FileNotFoundError:
                stale.append(name)
        else:
            os.makedirs(args.out, exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(dump(obj))
            print("wrote", os.path.relpath(path, REPO))
    if stale:
        print("out of date:", ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
