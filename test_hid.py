import argparse
import hmac
import hashlib
import os
import hid

VID = 0xCAFE
PID = 0x4011

REQ_VERSION = 1
CMD_SIGN = 1
DOMAIN_SUDO = 1

DEFAULT_MASTER_SECRET = bytes([
    0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23,
    0x30, 0x31, 0x32, 0x33, 0x40, 0x41, 0x42, 0x43,
    0x50, 0x51, 0x52, 0x53, 0x60, 0x61, 0x62, 0x63,
    0x70, 0x71, 0x72, 0x73, 0x80, 0x81, 0x82, 0x83
])

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send sign command to RP2350 token and verify returned MAC."
    )
    parser.add_argument(
        "--secret-hex",
        default=None,
        help="32-byte master secret in hex (64 hex chars). Defaults to built-in demo secret.",
    )
    return parser.parse_args()

def get_master_secret(secret_hex: str | None) -> bytes:
    if secret_hex is None:
        return DEFAULT_MASTER_SECRET
    secret = bytes.fromhex(secret_hex)
    if len(secret) != 32:
        raise SystemExit("secret must be exactly 32 bytes (64 hex chars)")
    return secret

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, out_len: int) -> bytes:
    """RFC5869 HKDF-SHA256 used to mirror firmware-side key derivation."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < out_len:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:out_len]

def derive_device_root_key(master_secret: bytes, uid_bytes: bytes) -> bytes:
    return hkdf_sha256(master_secret, uid_bytes, b"rp2350-token-root-v1", 32)

def derive_domain_key(root_key: bytes, domain: int) -> bytes:
    label = b"rp2350-token-domain:\x00" + bytes([domain])
    return hmac.new(root_key, label, hashlib.sha256).digest()

args = parse_args()
master_secret = get_master_secret(args.secret_hex)

print("Enumerating devices:")
selected = None
for d in hid.enumerate():
    if d["vendor_id"] == VID and d["product_id"] == PID:
        print("Found:", d)
        if selected is None:
            selected = d

if selected is None:
    raise SystemExit("Token not found")

serial = selected.get("serial_number", "")
if not serial:
    raise SystemExit("Device has no serial_number; cannot derive UID-based key")

try:
    uid_bytes = bytes.fromhex(serial)
except ValueError as exc:
    raise SystemExit(f"serial_number is not hex ({serial!r})") from exc

device_root_key = derive_device_root_key(master_secret, uid_bytes)
print("serial    :", serial)

challenge = os.urandom(32)

pkt = bytearray(64)
pkt[0] = REQ_VERSION
pkt[1] = CMD_SIGN
pkt[2] = DOMAIN_SUDO
pkt[3] = 0
pkt[4:36] = challenge

# Open the exact device we enumerated so serial->key derivation always matches.
dev = hid.Device(path=selected["path"])
dev.write(b"\x00" + bytes(pkt))
resp = bytes(dev.read(64, timeout=5000))
dev.close()

print("challenge :", challenge.hex())
print("response  :", resp.hex())

if len(resp) != 64:
    raise SystemExit("Bad response length")

version = resp[0]
status = resp[1]
domain = resp[2]
flags = resp[3]
mac = resp[4:36]
counter = int.from_bytes(resp[36:40], "little")

print("version   :", version)
print("status    :", status)
print("domain    :", domain)
print("flags     :", flags)
print("mac       :", mac.hex())
print("counter   :", counter)

if status == 0:
    domain_key = derive_domain_key(device_root_key, DOMAIN_SUDO)
    signed_msg = bytes([REQ_VERSION, DOMAIN_SUDO]) + counter.to_bytes(4, "little") + challenge
    expected = hmac.new(domain_key, signed_msg, hashlib.sha256).digest()

    print("expected  :", expected.hex())
    print("match     :", mac == expected)
else:
    print("No MAC verification due to non-zero status")
