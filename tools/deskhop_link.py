"""DeskHop Link reference implementation (helper app <-> box).

The wire format is protocol.md in Erik's notes (reviewed 2026-10-16). This module is the
spec in code form: the firmware, the Windows app and the Swift app must reproduce the
vectors in test-vectors/link/, which tools/gen-link-vectors.py writes from this module.

What it covers:
  - 64-byte reports with the frame-start flag, and the resync rules (Reassembler)
  - the 3-byte frame header and the type bands
  - signed frames: u64 counter + 16-byte HMAC-SHA256 tag, receiver counter rules
  - pairing keys over P-256 ECDH (via the `cryptography` package), HKDF-SHA256 derivations
  - body layouts for every message type in the catalogue

It deliberately has no I/O, no timers and no box state machine beyond what the
receive rules need. Integers are little-endian; public keys are 64 bytes X || Y big-endian.
"""

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

# ---------------------------------------------------------------------------
# Reports and frames

REPORT_SIZE = 64
REPORT_PAYLOAD = REPORT_SIZE - 1    # byte 0 is the frame-start flag
FLAG_CONTINUE = 0
FLAG_START = 1
HEADER_SIZE = 3                     # type u8, len u16 LE
MAX_LEN = 1024                      # max value of len; larger is malformed

COUNTER_SIZE = 8
TAG_SIZE = 16
AUTH_SIZE = COUNTER_SIZE + TAG_SIZE

# protocol.md doesn't give the value of the `proto` field; 1 matches the
# "deskhop-link/1" KDF labels.
PROTO_VERSION = 1


def encode_frame(type_, body):
    """Header + body. `body` is everything counted in len (auth prefix included)."""
    if not 0x01 <= type_ <= 0xFF:
        raise ValueError("type 0x00 is padding, never a frame type")
    if len(body) > MAX_LEN:
        raise ValueError("len %d exceeds %d" % (len(body), MAX_LEN))
    return struct.pack("<BH", type_, len(body)) + bytes(body)


def parse_header(frame):
    type_, length = struct.unpack_from("<BH", frame, 0)
    return type_, length


def split_reports(frame):
    """A frame -> its 64-byte reports. The first has flag 1, the rest flag 0, tail zero-padded."""
    reports = []
    for i in range(0, len(frame), REPORT_PAYLOAD):
        chunk = frame[i:i + REPORT_PAYLOAD]
        flag = FLAG_START if i == 0 else FLAG_CONTINUE
        reports.append(bytes([flag]) + chunk + bytes(REPORT_PAYLOAD - len(chunk)))
    return reports


def report_count(length):
    """Reports needed for a frame whose header says `length`."""
    return -(-(HEADER_SIZE + length) // REPORT_PAYLOAD)


class Reassembler:
    """Turns a stream of 64-byte reports back into frames, applying protocol.md's resync rules.

    feed() returns a complete frame (bytes) or None. Dropped input is silent; `last_drop`
    names why the most recent report caused a drop, for tests and debugging only.
    """

    def __init__(self):
        self._buf = None
        self._need = 0
        self.last_drop = None

    @property
    def in_progress(self):
        return self._buf is not None

    def feed(self, report):
        if len(report) != REPORT_SIZE:
            raise ValueError("report must be %d bytes" % REPORT_SIZE)
        self.last_drop = None
        flag, payload = report[0], report[1:]

        if flag == FLAG_START:
            if self._buf is not None:
                self.last_drop = "frame interrupted"     # it lost a report
                self._buf = None
            return self._start(payload)

        if flag == FLAG_CONTINUE:
            if self._buf is None:
                self.last_drop = "orphan report"         # tail of a frame whose head was lost
                return None
            return self._take(payload)

        # protocol.md defines only 0 and 1. Not decided: the reference drops the report and
        # any frame in progress. No vector depends on this.
        self._buf = None
        self.last_drop = "bad flag"
        return None

    def _start(self, payload):
        type_, length = struct.unpack_from("<BH", payload, 0)
        if type_ == 0x00:
            self.last_drop = "type 0x00"
            return None
        if length > MAX_LEN:
            self.last_drop = "len over max"
            return None
        self._buf = bytearray()
        self._need = HEADER_SIZE + length
        return self._take(payload)

    def _take(self, payload):
        n = min(self._need - len(self._buf), REPORT_PAYLOAD)
        self._buf += payload[:n]
        if len(self._buf) < self._need:
            return None
        frame = bytes(self._buf)
        self._buf = None
        if any(payload[n:]):
            self.last_drop = "non-padding tail"
            return None
        return frame


# ---------------------------------------------------------------------------
# Types, bands, directions

STATUS_GET = 0x01
STATUS = 0x02
PAIR_REQUEST = 0x03
PAIR_CHALLENGE = 0x04
PAIR_RESULT = 0x05
HELLO = 0x06
HELLO_REFUSED = 0x07
HELLO_ACK = 0x10
HEARTBEAT = 0x11
STATE = 0x12
SESSION_END = 0x14
EDGE_HIT = 0x20
CURSOR_WARP = 0x21
FOREGROUND_APP = 0x22               # reserved, Phase X; body not defined
UPLOAD_START = 0x30
UPLOAD_READY = 0x31
UPLOAD_DATA = 0x32
UPLOAD_ABORT = 0x33
UPLOAD_RESULT = 0x34
READ_REQUEST = 0x40
READ_BEGIN = 0x41
READ_DATA = 0x42

H2B = "h2b"
B2H = "b2h"

NAMES = {
    STATUS_GET: "STATUS_GET", STATUS: "STATUS", PAIR_REQUEST: "PAIR_REQUEST",
    PAIR_CHALLENGE: "PAIR_CHALLENGE", PAIR_RESULT: "PAIR_RESULT", HELLO: "HELLO",
    HELLO_REFUSED: "HELLO_REFUSED", HELLO_ACK: "HELLO_ACK", HEARTBEAT: "HEARTBEAT",
    STATE: "STATE", SESSION_END: "SESSION_END", EDGE_HIT: "EDGE_HIT",
    CURSOR_WARP: "CURSOR_WARP", FOREGROUND_APP: "FOREGROUND_APP",
    UPLOAD_START: "UPLOAD_START", UPLOAD_READY: "UPLOAD_READY", UPLOAD_DATA: "UPLOAD_DATA",
    UPLOAD_ABORT: "UPLOAD_ABORT", UPLOAD_RESULT: "UPLOAD_RESULT",
    READ_REQUEST: "READ_REQUEST", READ_BEGIN: "READ_BEGIN", READ_DATA: "READ_DATA",
}

DIRECTION = {
    STATUS_GET: H2B, STATUS: B2H, PAIR_REQUEST: H2B, PAIR_CHALLENGE: B2H, PAIR_RESULT: B2H,
    HELLO: H2B, HELLO_REFUSED: B2H, HELLO_ACK: B2H, HEARTBEAT: H2B, STATE: B2H,
    SESSION_END: H2B, EDGE_HIT: H2B, CURSOR_WARP: B2H, FOREGROUND_APP: H2B,
    UPLOAD_START: H2B, UPLOAD_READY: B2H, UPLOAD_DATA: H2B, UPLOAD_ABORT: H2B,
    UPLOAD_RESULT: B2H, READ_REQUEST: H2B, READ_BEGIN: B2H, READ_DATA: B2H,
}


@dataclass(frozen=True)
class Band:
    first: int
    last: int
    signed: bool
    queue: str          # "priority" or "bulk"
    holds: str


BANDS = (
    Band(0x01, 0x0F, False, "priority", "status, pairing, hello"),
    Band(0x10, 0x2F, True, "priority", "session, state, edges, warps"),
    Band(0x30, 0x3F, True, "bulk", "upload"),
    Band(0x40, 0x4F, False, "bulk", "Get configuration"),
)


def band(type_):
    """The band for a type byte, or None for 0x00 (padding) and 0x50-0xFF (reserved, dropped)."""
    for b in BANDS:
        if b.first <= type_ <= b.last:
            return b
    return None


def is_signed(type_):
    b = band(type_)
    return b is not None and b.signed


# ---------------------------------------------------------------------------
# Message bodies
#
# Fixed fields are (name, struct code). "Ns" fields are bytes. A trailing ("data", None)
# takes the rest of the body. STATUS has a variable device list and its own codec.

FIELDS = {
    STATUS_GET: [("corr", "I")],
    PAIR_REQUEST: [("corr", "I"), ("helper_pub", "64s")],
    PAIR_CHALLENGE: [("corr", "I"), ("board_pub", "64s"), ("attempt", "B"), ("code_ct", "4s")],
    PAIR_RESULT: [("corr", "I"), ("result", "B"), ("key_id", "8s")],
    HELLO: [("corr", "I"), ("proto", "H"), ("os", "B"), ("app_version", "H"),
            ("key_id", "8s"), ("helper_nonce", "16s")],
    HELLO_REFUSED: [("corr", "I"), ("reason", "B")],
    HELLO_ACK: [("corr", "I"), ("proto", "H"), ("board_nonce", "16s"), ("computer", "B"),
                ("board_type", "B"), ("layout", "B")],
    HEARTBEAT: [],
    STATE: [("active", "B"), ("layout", "B"), ("profile", "B"), ("box_state", "B")],
    SESSION_END: [],
    EDGE_HIT: [("edge", "B"), ("pos", "H")],
    CURSOR_WARP: [("edge", "B"), ("pos", "H")],
    UPLOAD_START: [("total_len", "I"), ("crc32", "I"), ("schema", "H")],
    UPLOAD_READY: [("upload_id", "I"), ("max_chunk", "H")],
    UPLOAD_DATA: [("upload_id", "I"), ("offset", "I"), ("data", None)],
    UPLOAD_ABORT: [("upload_id", "I")],
    UPLOAD_RESULT: [("upload_id", "I"), ("status", "B"), ("detail", "H")],
    READ_REQUEST: [("corr", "I")],
    READ_BEGIN: [("corr", "I"), ("status", "B"), ("total_len", "I"), ("crc32", "I"),
                 ("schema", "H")],
    READ_DATA: [("corr", "I"), ("offset", "I"), ("data", None)],
}

READ_DATA_MAX = 512
FW_TAG_SIZE = 16
DEVICE_NAME_MAX = 32

_STATUS_FIXED = [
    ("corr", "I"), ("proto", "H"), ("fw_tag", "16s"), ("schema", "H"), ("board_type", "B"),
    ("computer", "B"), ("paired", "B"), ("box_state", "B"), ("max_profiles", "B"),
    ("max_rules", "B"), ("max_name", "B"), ("max_blob", "I"), ("os_a", "B"), ("os_b", "B"),
    ("ss_hash_a", "I"), ("ss_hash_b", "I"), ("device_count", "B"),
]
_STATUS_DEVICE = [("board", "B"), ("vid", "H"), ("pid", "H"), ("poll_us", "H"), ("name_len", "B")]


def _fmt(specs):
    return "<" + "".join(code for _, code in specs)


class MalformedBody(ValueError):
    pass


def encode_body(type_, fields):
    """Message body (no auth prefix) from a dict of fields."""
    if type_ == STATUS:
        return _encode_status(fields)
    specs = FIELDS[type_]
    fixed = [s for s in specs if s[1] is not None]
    out = struct.pack(_fmt(fixed), *(fields[name] for name, _ in fixed))
    if specs and specs[-1][1] is None:
        data = bytes(fields["data"])
        if type_ == READ_DATA and len(data) > READ_DATA_MAX:
            raise ValueError("READ_DATA carries at most %d bytes" % READ_DATA_MAX)
        out += data
    return out


def decode_body(type_, body):
    """Dict of fields from a message body. Strict: wrong length raises MalformedBody."""
    if type_ == STATUS:
        return _decode_status(body)
    specs = FIELDS[type_]
    fixed = [s for s in specs if s[1] is not None]
    fmt = _fmt(fixed)
    size = struct.calcsize(fmt)
    has_tail = bool(specs) and specs[-1][1] is None
    if len(body) < size or (not has_tail and len(body) != size):
        raise MalformedBody("%s body is %d bytes, expected %s%d"
                            % (NAMES[type_], len(body), ">=" if has_tail else "", size))
    out = dict(zip((name for name, _ in fixed), struct.unpack_from(fmt, body, 0)))
    if has_tail:
        out["data"] = bytes(body[size:])
        if type_ == READ_DATA and len(out["data"]) > READ_DATA_MAX:
            raise MalformedBody("READ_DATA carries at most %d bytes" % READ_DATA_MAX)
    return out


def _encode_status(f):
    tag = f["fw_tag"].encode("ascii")
    if len(tag) > FW_TAG_SIZE:
        raise ValueError("fw_tag longer than %d" % FW_TAG_SIZE)
    devices = f["devices"]
    values = dict(f, fw_tag=tag.ljust(FW_TAG_SIZE, b"\0"), device_count=len(devices))
    out = struct.pack(_fmt(_STATUS_FIXED), *(values[name] for name, _ in _STATUS_FIXED))
    for d in devices:
        name = d["name"].encode("utf-8")
        if len(name) > DEVICE_NAME_MAX:
            raise ValueError("device name longer than %d bytes" % DEVICE_NAME_MAX)
        out += struct.pack(_fmt(_STATUS_DEVICE), d["board"], d["vid"], d["pid"], d["poll_us"],
                           len(name)) + name
    return out


def _decode_status(body):
    fmt = _fmt(_STATUS_FIXED)
    size = struct.calcsize(fmt)
    if len(body) < size:
        raise MalformedBody("STATUS body shorter than its fixed part")
    f = dict(zip((n for n, _ in _STATUS_FIXED), struct.unpack_from(fmt, body, 0)))
    f["fw_tag"] = f["fw_tag"].rstrip(b"\0").decode("ascii")
    count = f.pop("device_count")
    pos = size
    dfmt = _fmt(_STATUS_DEVICE)
    dsize = struct.calcsize(dfmt)
    devices = []
    for _ in range(count):
        if len(body) < pos + dsize:
            raise MalformedBody("STATUS device list truncated")
        board, vid, pid, poll_us, name_len = struct.unpack_from(dfmt, body, pos)
        pos += dsize
        if name_len > DEVICE_NAME_MAX or len(body) < pos + name_len:
            raise MalformedBody("STATUS device name truncated or too long")
        name = body[pos:pos + name_len].decode("utf-8")
        pos += name_len
        devices.append({"board": board, "vid": vid, "pid": pid, "poll_us": poll_us, "name": name})
    if pos != len(body):
        raise MalformedBody("STATUS has trailing bytes")
    f["devices"] = devices
    return f


# ---------------------------------------------------------------------------
# Signed frames

class AuthError(ValueError):
    pass


def compute_tag(key, type_, length, counter, message):
    """First 16 bytes of HMAC-SHA256(key, type || len || counter || message body)."""
    mac_input = struct.pack("<BHQ", type_, length, counter) + bytes(message)
    return hmac.new(key, mac_input, hashlib.sha256).digest()[:TAG_SIZE]


def encode_signed_frame(type_, key, counter, message):
    if not is_signed(type_):
        raise ValueError("0x%02x is not in a signed band" % type_)
    length = AUTH_SIZE + len(message)
    tag = compute_tag(key, type_, length, counter, message)
    return encode_frame(type_, struct.pack("<Q", counter) + tag + bytes(message))


def open_signed_frame(frame, key):
    """(counter, message body) if the tag verifies under `key`; AuthError otherwise.

    Counter freshness is the caller's job (see Receiver)."""
    type_, length = parse_header(frame)
    body = frame[HEADER_SIZE:]
    if len(body) != length or length < AUTH_SIZE:
        raise AuthError("too short for the auth prefix")
    counter = struct.unpack_from("<Q", body, 0)[0]
    tag = body[COUNTER_SIZE:AUTH_SIZE]
    message = body[AUTH_SIZE:]
    if not hmac.compare_digest(tag, compute_tag(key, type_, length, counter, message)):
        raise AuthError("bad tag")
    return counter, bytes(message)


class Receiver:
    """One direction of one session, on the receiving side.

    `role` is "box" (accepts h2b types, key k_h2b) or "app" (accepts b2h types, key k_b2h).
    accept() returns (counter, message body) or None for a silent drop; `last_drop` says why.
    """

    def __init__(self, role, key):
        if role not in ("box", "app"):
            raise ValueError(role)
        self.role = role
        self.key = key
        self.highest = None         # nothing accepted yet: any counter is newer
        self.last_drop = None

    def _wanted_direction(self):
        return H2B if self.role == "box" else B2H

    def check(self, frame):
        """Verify without recording. Returns (counter, message) or None and sets last_drop."""
        self.last_drop = None
        type_, _ = parse_header(frame)
        if not is_signed(type_):
            self.last_drop = "not a signed type"
            return None
        if DIRECTION.get(type_) != self._wanted_direction():
            self.last_drop = "wrong direction"
            return None
        try:
            counter, message = open_signed_frame(frame, self.key)
        except AuthError as e:
            self.last_drop = str(e)
            return None
        if self.highest is not None and counter <= self.highest:
            self.last_drop = "stale counter"
            return None
        return counter, message

    def accept(self, frame):
        result = self.check(frame)
        if result is not None:
            self.highest = result[0]    # recorded only after the tag verifies
        return result


class Sender:
    """One direction of one session, on the sending side. Counters start at 0."""

    def __init__(self, key):
        self.key = key
        self.next_counter = 0

    def frame(self, type_, message):
        f = encode_signed_frame(type_, self.key, self.next_counter, message)
        self.next_counter += 1
        return f


class BoxSessionSlot:
    """The box's session state for one computer: a confirmed session plus at most one pending.

    A HELLO_ACK makes new keys pending; they replace the confirmed ones only when the box
    accepts the first app frame signed under them (protocol.md, Session step 4).
    """

    def __init__(self):
        self.confirmed = None       # Receiver for k_h2b
        self.pending = None
        self.last_drop = None

    def set_pending(self, k_h2b):
        self.pending = Receiver("box", k_h2b)

    def receive(self, frame):
        """(counter, message) or None. Tries the confirmed session, then the pending one."""
        self.last_drop = "no session"
        if self.confirmed is not None:
            r = self.confirmed.accept(frame)
            if r is not None:
                return r
            self.last_drop = self.confirmed.last_drop
        if self.pending is not None:
            r = self.pending.accept(frame)
            if r is not None:
                self.confirmed, self.pending = self.pending, None
                return r
            if self.confirmed is None:
                self.last_drop = self.pending.last_drop
        return None


# ---------------------------------------------------------------------------
# Keys

HASH_LEN = 32
KEY_LEN = 32
INFO_PAIR = b"deskhop-link/1 pair"
INFO_CODE = b"deskhop-link/1 code"
INFO_ID = b"deskhop-link/1 id"
INFO_H2B = b"deskhop-link/1 h2b"
INFO_B2H = b"deskhop-link/1 b2h"
PAD_LEN = 4
KEY_ID_LEN = 8
NONCE_LEN = 16
PUBLIC_KEY_LEN = 64


def hkdf_extract(salt, ikm):
    # RFC 5869: an absent salt is HashLen zero bytes (same HMAC key as an empty one).
    return hmac.new(salt if salt else bytes(HASH_LEN), ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length=KEY_LEN):
    okm, block = b"", b""
    i = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        okm += block
        i += 1
    return okm[:length]


def hkdf(ikm, salt, info, length=KEY_LEN):
    """HKDF-SHA256. protocol.md always takes a 32-byte output and truncates where it says
    "first N bytes"; for HKDF that equals asking for N bytes."""
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def private_key_from_scalar(d):
    """P-256 private key from a 32-byte big-endian scalar."""
    return ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1())


def private_scalar(priv):
    return priv.private_numbers().private_value.to_bytes(32, "big")


def public_bytes(priv_or_pub):
    """64-byte X || Y, big-endian, no 0x04 prefix."""
    pub = priv_or_pub.public_key() if hasattr(priv_or_pub, "public_key") else priv_or_pub
    n = pub.public_numbers()
    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


def load_public(pub64):
    """64-byte public key -> key object. Raises ValueError if the point isn't on P-256."""
    if len(pub64) != PUBLIC_KEY_LEN:
        raise ValueError("public key must be 64 bytes")
    x = int.from_bytes(pub64[:32], "big")
    y = int.from_bytes(pub64[32:], "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def ecdh(priv, peer_pub64):
    """ss: the 32-byte X coordinate of the shared point."""
    return priv.exchange(ec.ECDH(), load_public(peer_pub64))


def transcript_hash(helper_pub, board_pub):
    return hashlib.sha256(bytes(helper_pub) + bytes(board_pub)).digest()


def derive_k_pair(ss, th):
    return hkdf(ss, th, INFO_PAIR)


def derive_pad(ss, th, attempt):
    if not 1 <= attempt <= 0xFF:
        raise ValueError("attempt is a u8 starting at 1")
    return hkdf(ss, th, INFO_CODE + bytes([attempt]))[:PAD_LEN]


def derive_key_id(k_pair):
    return hkdf(k_pair, b"", INFO_ID)[:KEY_ID_LEN]


def derive_session_keys(k_pair, helper_nonce, board_nonce):
    """(k_h2b, k_b2h)."""
    if len(helper_nonce) != NONCE_LEN or len(board_nonce) != NONCE_LEN:
        raise ValueError("nonces are 16 bytes")
    salt = bytes(helper_nonce) + bytes(board_nonce)
    return hkdf(k_pair, salt, INFO_H2B), hkdf(k_pair, salt, INFO_B2H)


@dataclass(frozen=True)
class PairingKeys:
    ss: bytes
    th: bytes
    k_pair: bytes
    key_id: bytes

    def pad(self, attempt):
        return derive_pad(self.ss, self.th, attempt)


def pairing_keys(own_priv, helper_pub, board_pub, peer_pub):
    """Everything either side derives after the ECDH. `peer_pub` is the other side's key."""
    ss = ecdh(own_priv, peer_pub)
    th = transcript_hash(helper_pub, board_pub)
    k_pair = derive_k_pair(ss, th)
    return PairingKeys(ss, th, k_pair, derive_key_id(k_pair))


# ---------------------------------------------------------------------------
# The typed code

# A-Z minus I, L, O as HID keyboard usage IDs.
CODE_ALPHABET = tuple(u for u in range(0x04, 0x1E) if u not in (0x0C, 0x0F, 0x12))
CODE_LEN = 4


def code_from_letters(letters):
    code = bytes(0x04 + ord(c) - ord("A") for c in letters.upper())
    check_code(code)
    return code


def code_letters(code):
    """US-layout letters for display in tests. The app renders usages in the OS layout."""
    return "".join(chr(ord("A") + u - 0x04) for u in code)


def check_code(code):
    if len(code) != CODE_LEN or any(u not in CODE_ALPHABET for u in code):
        raise ValueError("code must be 4 usages from A-Z minus I, L, O")


def xor_code(code_or_ct, pad):
    """code_ct = code XOR pad_n; the same call decrypts."""
    return bytes(a ^ b for a, b in zip(code_or_ct, pad, strict=True))
