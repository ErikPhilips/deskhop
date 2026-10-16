"""Checks that test-vectors/link/ round-trips through the reference module.

    python -m unittest discover -s tools -p "test_link*.py" -v

Where it can, a check rebuilds a value from the vector's own inputs rather than from the
generator's code path, and cross-checks HKDF against the `cryptography` package.
"""

import hashlib
import hmac
import importlib.util
import json
import os
import struct
import sys
import unittest
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
import deskhop_link as dl  # noqa: E402

VECTORS = os.path.join(os.path.dirname(TOOLS), "test-vectors", "link")


def load(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as f:
        return json.load(f)


def b(h):
    return bytes.fromhex(h)


def lib_hkdf(ikm, salt, info, length=32):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt or None, info=info).derive(ikm)


def fields_from_json(type_, fields):
    """JSON fields -> the dict encode_body takes (hex strings back to bytes)."""
    if type_ == dl.STATUS:
        return fields
    out = dict(fields)
    for name, code in dl.FIELDS[type_]:
        if code is None or code.endswith("s"):
            out[name] = b(fields[name])
    return out


def reassemble(reports):
    r = dl.Reassembler()
    frames = []
    for rep in reports:
        f = r.feed(b(rep))
        if f is not None:
            frames.append(f)
    return frames, r


class GeneratorIsCurrent(unittest.TestCase):
    def test_files_match_generator(self):
        spec = importlib.util.spec_from_file_location("gen", os.path.join(TOOLS, "gen-link-vectors.py"))
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        for name, obj in gen.build_all().items():
            with self.subTest(name):
                self.assertEqual(load(name), json.loads(gen.dump(obj)),
                                 "%s is stale: run tools/gen-link-vectors.py" % name)


class Framing(unittest.TestCase):
    v = load("framing.json")

    def test_encode(self):
        for case in self.v["encode"]:
            with self.subTest(case["name"]):
                frame = b(case["frame"])
                reports = [b(r) for r in case["reports"]]
                self.assertEqual(dl.split_reports(frame), reports)
                self.assertEqual(len(reports), dl.report_count(dl.parse_header(frame)[1]))
                self.assertTrue(all(len(r) == 64 for r in reports))
                self.assertEqual(reports[0][0], 1)
                self.assertTrue(all(r[0] == 0 for r in reports[1:]))
                self.assertEqual(b"".join(r[1:] for r in reports).rstrip(b"\0"), frame.rstrip(b"\0"))
                self.assertEqual(reassemble(case["reports"])[0], [frame])

    def test_decode(self):
        for case in self.v["decode"]:
            with self.subTest(case["name"]):
                frames, r = reassemble(case["reports"])
                self.assertEqual(frames, [b(f) for f in case["frames"]])
                self.assertFalse(r.in_progress)

    def test_bands(self):
        by_type = {int(t["type"], 16): t for t in self.v["types"]}
        for t in range(256):
            bd = dl.band(t)
            in_table = [x for x in self.v["bands"] if int(x["first"], 16) <= t <= int(x["last"], 16)]
            if t == 0 or t >= 0x50:
                self.assertIsNone(bd)
                self.assertEqual(in_table, [])
                continue
            self.assertEqual(len(in_table), 1)
            self.assertEqual((bd.signed, bd.queue), (in_table[0]["signed"], in_table[0]["queue"]))
            if t in by_type:
                self.assertEqual(dl.DIRECTION[t], by_type[t]["dir"])
                self.assertEqual(dl.NAMES[t], by_type[t]["name"])

    def test_direction(self):
        """Any type in the wrong direction is dropped, signed or not."""
        dirs = {int(t["type"], 16): t["dir"] for t in self.v["types"]}
        for t in range(256):
            self.assertEqual(dl.wanted_by("box", t), dirs.get(t) == "h2b", hex(t))
            self.assertEqual(dl.wanted_by("app", t), dirs.get(t) == "b2h", hex(t))


class Kdf(unittest.TestCase):
    v = load("kdf.json")

    def test_pairing(self):
        for p in self.v["pairing"]:
            with self.subTest(p["name"]):
                helper = dl.private_key_from_scalar(b(p["helper_priv"]))
                board = dl.private_key_from_scalar(b(p["board_priv"]))
                hp, bp = b(p["helper_pub"]), b(p["board_pub"])
                self.assertEqual(dl.public_bytes(helper), hp)
                self.assertEqual(dl.public_bytes(board), bp)
                # both sides of the ECDH agree on ss
                self.assertEqual(dl.ecdh(helper, bp), b(p["ss"]))
                self.assertEqual(dl.ecdh(board, hp), b(p["ss"]))
                ss, th = b(p["ss"]), b(p["th"])
                self.assertEqual(hashlib.sha256(hp + bp).digest(), th)
                self.assertEqual(dl.hkdf_extract(th, ss), b(p["k_pair_prk"]))
                for k_pair in (dl.derive_k_pair(ss, th), lib_hkdf(ss, th, b"deskhop-link/1 pair")):
                    self.assertEqual(k_pair, b(p["k_pair"]))
                k_pair = b(p["k_pair"])
                self.assertEqual(dl.derive_key_id(k_pair), b(p["key_id"]))
                self.assertEqual(lib_hkdf(k_pair, b"", b"deskhop-link/1 id")[:8], b(p["key_id"]))
                for a in p["attempts"]:
                    n = a["attempt"]
                    pad = b(a["pad"])
                    self.assertEqual(dl.derive_pad(ss, th, n), pad)
                    self.assertEqual(lib_hkdf(ss, th, b"deskhop-link/1 code" + bytes([n]))[:4], pad)
                    code = b(a["code"])
                    dl.check_code(code)
                    self.assertEqual(dl.code_letters(code), a["letters"])
                    self.assertEqual(dl.xor_code(code, pad), b(a["code_ct"]))
                    self.assertEqual(dl.xor_code(b(a["code_ct"]), pad), code)
                pads = [a["pad"] for a in p["attempts"]]
                self.assertEqual(len(set(pads)), len(pads), "a pad was reused")

    def test_session(self):
        for s in self.v["session"]:
            with self.subTest(s["name"]):
                hn, bn, k_pair = b(s["helper_nonce"]), b(s["board_nonce"]), b(s["k_pair"])
                self.assertEqual(hn + bn, b(s["salt"]))
                self.assertEqual(dl.derive_session_keys(k_pair, hn, bn), (b(s["k_h2b"]), b(s["k_b2h"])))
                self.assertEqual(lib_hkdf(k_pair, hn + bn, b"deskhop-link/1 h2b"), b(s["k_h2b"]))
                self.assertEqual(lib_hkdf(k_pair, hn + bn, b"deskhop-link/1 b2h"), b(s["k_b2h"]))

    def test_invalid_public_keys(self):
        board = dl.private_key_from_scalar(b(self.v["pairing"][0]["board_priv"]))
        for k in self.v["invalid_public_keys"]:
            with self.subTest(k["name"]):
                with self.assertRaises(ValueError):
                    dl.load_public(b(k["pub"]))
                with self.assertRaises(ValueError):
                    dl.ecdh(board, b(k["pub"]))

    def test_alphabet(self):
        self.assertEqual(len(dl.CODE_ALPHABET), 23)
        self.assertNotIn(0x0C, dl.CODE_ALPHABET)   # I
        self.assertNotIn(0x0F, dl.CODE_ALPHABET)   # L
        self.assertNotIn(0x12, dl.CODE_ALPHABET)   # O


def check_message(tc, m, keys):
    type_ = int(m["type"], 16)
    body = b(m["body"])
    frame = b(m["frame"])
    tc.assertEqual(dl.NAMES[type_], m["name"])
    tc.assertEqual(dl.DIRECTION[type_], m["dir"])
    tc.assertEqual(dl.is_signed(type_), m["signed"])
    # fields <-> body, both ways
    tc.assertEqual(dl.encode_body(type_, fields_from_json(type_, m["fields"])), body)
    decoded = dl.decode_body(type_, body)
    tc.assertEqual(dl.encode_body(type_, decoded), body)
    # frame layout
    t, length = struct.unpack_from("<BH", frame, 0)
    tc.assertEqual(t, type_)
    tc.assertEqual(length, len(frame) - 3)
    tc.assertLessEqual(length, dl.MAX_LEN)
    if m["signed"]:
        key = keys[m["key"]]
        counter = m["counter"]
        tc.assertEqual(length, 24 + len(body))
        tc.assertEqual(frame[3:11], struct.pack("<Q", counter))
        tc.assertEqual(frame[11:27], b(m["tag"]))
        tc.assertEqual(frame[27:], body)
        expect_tag = hmac.new(key, frame[:3] + frame[3:11] + body, hashlib.sha256).digest()[:16]
        tc.assertEqual(b(m["tag"]), expect_tag)
        tc.assertEqual(dl.open_signed_frame(frame, key), (counter, body))
        tc.assertEqual(dl.encode_signed_frame(type_, key, counter, body), frame)
    else:
        tc.assertEqual(frame[3:], body)
    # reports
    frames, _ = reassemble(m["reports"])
    tc.assertEqual(frames, [frame])
    tc.assertEqual([r.hex() for r in dl.split_reports(frame)], m["reports"])
    return type_, decoded


class Messages(unittest.TestCase):
    v = load("messages.json")

    def test_messages(self):
        keys = {"k_h2b": b(self.v["keys"]["k_h2b"]), "k_b2h": b(self.v["keys"]["k_b2h"])}
        seen = set()
        for i, m in enumerate(self.v["messages"]):
            with self.subTest("%d %s" % (i, m["name"])):
                seen.add(check_message(self, m, keys)[0])
        defined = set(dl.NAMES) - {dl.FOREGROUND_APP}
        self.assertEqual(seen, defined, "every defined type has a vector")

    def test_status_layout(self):
        status = [m for m in self.v["messages"] if m["name"] == "STATUS"]
        for m in status:
            body = b(m["body"])
            f = m["fields"]
            self.assertEqual(body[6:22], f["fw_tag"].encode().ljust(16, b"\0"))
            fixed = 4 + 2 + 16 + 2 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 4 + 1 + 1 + 4 + 4 + 1
            self.assertEqual(body[fixed - 1], len(f["devices"]))
            expect = fixed + sum(8 + len(d["name"].encode("utf-8")) for d in f["devices"])
            self.assertEqual(len(body), expect)

    def test_malformed(self):
        for m in self.v["malformed"]:
            with self.subTest(m["name"]):
                with self.assertRaises(dl.MalformedBody):
                    dl.decode_body(int(m["type"], 16), b(m["body"]))

    def test_app_version(self):
        self.assertEqual(dl.app_version(1, 0), 0x0100)
        self.assertEqual(dl.app_version(2, 13), 0x020D)

    def test_strict_lengths(self):
        with self.assertRaises(dl.MalformedBody):
            dl.decode_body(dl.EDGE_HIT, bytes(4))
        with self.assertRaises(dl.MalformedBody):
            dl.decode_body(dl.HELLO, bytes(10))
        with self.assertRaises(dl.MalformedBody):
            dl.decode_body(dl.READ_DATA, bytes(8 + 513))


class Verify(unittest.TestCase):
    v = load("verify.json")

    def test_scenarios(self):
        for sc in self.v["scenarios"]:
            if "start" in sc:
                slot = dl.BoxSessionSlot()
                slot.confirmed = dl.Receiver("box", b(sc["start"]["confirmed"]["k_h2b"]))
                slot.confirmed.highest = sc["start"]["confirmed"]["highest"]
                slot.set_pending(b(sc["start"]["pending"]["k_h2b"]))
                names = {b(sc["start"][k]["k_h2b"]): sc["start"][k]["session"]
                         for k in ("confirmed", "pending")}
                receive = slot.receive
            else:
                rx = dl.Receiver(sc["role"], b(sc["key"]))
                rx.highest = sc["start_highest"]
                receive = rx.accept
            for step in sc["steps"]:
                with self.subTest(sc["name"] + ": " + step["note"]):
                    if step.get("event") == "pending":
                        slot.set_pending(b(step["k_h2b"]))
                        names[b(step["k_h2b"])] = step["session"]
                        self.assertEqual((names[slot.confirmed.key], names[slot.pending.key]),
                                         (step["confirmed_after"], step["pending_after"]))
                        continue
                    r = receive(b(step["frame"]))
                    if step["expect"] == "accept":
                        self.assertEqual(r, (step["counter"], b(step["message"])))
                    else:
                        self.assertIsNone(r)
                    if "start" in sc:
                        conf = names[slot.confirmed.key] if slot.confirmed else None
                        pend = names[slot.pending.key] if slot.pending else None
                        self.assertEqual((conf, pend), (step["confirmed_after"], step["pending_after"]))
                    else:
                        self.assertEqual(rx.highest, step["highest_after"])


class Transcript(unittest.TestCase):
    """Replays the transcript with each side deriving its keys from its own inputs only."""

    v = load("transcript.json")

    def test_replay(self):
        app_in, box_in = self.v["app"], self.v["box"]
        helper = dl.private_key_from_scalar(b(app_in["helper_priv"]))
        board = dl.private_key_from_scalar(b(box_in["board_priv"]))
        helper_pub = dl.public_bytes(helper)
        self.assertEqual(helper_pub, b(app_in["helper_pub"]))

        box_rx = dl.BoxSessionSlot()
        app_rx = None
        app_keys = box_keys = None
        app_k_pair = box_k_pair = None
        box_session = None
        read_buf = bytearray()
        read_total = read_crc = None
        upload_buf = bytearray()
        expected_counters = {dl.H2B: 0, dl.B2H: 0}

        for step in self.v["steps"]:
            with self.subTest("step %d %s" % (step["step"], step["name"])):
                frames, _ = reassemble(step["reports"])
                self.assertEqual(frames, [b(step["frame"])])
                frame = frames[0]
                type_, _ = dl.parse_header(frame)
                self.assertEqual(dl.NAMES[type_], step["name"])

                if dl.is_signed(type_):
                    self.assertEqual(step["counter"], expected_counters[step["dir"]],
                                     "counters run 0, 1, 2... per direction")
                    expected_counters[step["dir"]] += 1
                    if step["dir"] == dl.H2B:
                        r = box_rx.receive(frame)
                    else:
                        r = app_rx.accept(frame)
                    self.assertIsNotNone(r, "receiver dropped a transcript frame")
                    msg = r[1]
                else:
                    msg = frame[3:]
                f = dl.decode_body(type_, msg)

                if type_ == dl.READ_BEGIN:
                    read_total, read_crc = f["total_len"], f["crc32"]
                elif type_ == dl.READ_DATA:
                    self.assertEqual(f["offset"], len(read_buf))
                    read_buf += f["data"]
                    if f["offset"] + len(f["data"]) == read_total:
                        self.assertEqual(zlib.crc32(read_buf), read_crc)
                        self.assertEqual(bytes(read_buf), b(self.v["blobs"]["read"]))
                elif type_ == dl.PAIR_REQUEST:
                    box_keys = dl.pairing_keys(board, f["helper_pub"], dl.public_bytes(board),
                                               f["helper_pub"])
                elif type_ == dl.PAIR_CHALLENGE:
                    app_keys = dl.pairing_keys(helper, helper_pub, f["board_pub"], f["board_pub"])
                    code = dl.xor_code(f["code_ct"], app_keys.pad(f["attempt"]))
                    self.assertEqual(code, b(box_in["codes"][f["attempt"] - 1]))
                    dl.check_code(code)
                elif type_ == dl.PAIR_RESULT:
                    self.assertEqual(f["result"], 0)
                    self.assertEqual(f["key_id"], app_keys.key_id)
                    self.assertEqual(app_keys.k_pair, box_keys.k_pair)
                    app_k_pair, box_k_pair = app_keys.k_pair, box_keys.k_pair
                elif type_ == dl.HELLO:
                    self.assertEqual(f["key_id"], dl.derive_key_id(box_k_pair))
                    box_session = dl.derive_session_keys(box_k_pair, f["helper_nonce"],
                                                         b(box_in["board_nonce"]))
                    box_rx.set_pending(box_session[0])
                    hello_nonce = f["helper_nonce"]
                elif type_ == dl.HELLO_ACK:
                    # the app can only check this tag after deriving keys from board_nonce
                    pass
                elif type_ == dl.HEARTBEAT and box_rx.confirmed is not None:
                    self.assertEqual(box_rx.confirmed.key, box_session[0])
                    self.assertIsNone(box_rx.pending)
                elif type_ == dl.UPLOAD_DATA:
                    self.assertEqual(f["offset"], len(upload_buf))
                    upload_buf += f["data"]
                elif type_ == dl.UPLOAD_RESULT:
                    self.assertEqual(bytes(upload_buf), b(self.v["blobs"]["upload"]))
                    self.assertEqual(zlib.crc32(upload_buf), self.v["blobs"]["upload_crc32"])

            # HELLO_ACK: the app derives its session keys from the board_nonce it carries,
            # then checks the tag (done outside the subTest so later steps see app_rx).
            if step["name"] == "HELLO":
                ack = next(s for s in self.v["steps"] if s["name"] == "HELLO_ACK")
                ack_frame = b(ack["frame"])
                board_nonce = dl.decode_body(dl.HELLO_ACK, ack_frame[27:])["board_nonce"]
                k_h2b, k_b2h = dl.derive_session_keys(app_k_pair, hello_nonce, board_nonce)
                self.assertEqual((k_h2b, k_b2h), box_session)
                app_rx = dl.Receiver("app", k_b2h)

        self.assertEqual(box_rx.confirmed.key, b(self.v["derived"]["k_h2b"]))
        self.assertEqual(app_rx.key, b(self.v["derived"]["k_b2h"]))
        self.assertEqual(app_k_pair, b(self.v["derived"]["k_pair"]))


if __name__ == "__main__":
    unittest.main()
