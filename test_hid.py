import hmac
import hashlib
import os
import hid

VID = 0xCAFE
PID = 0x4011

REQ_VERSION = 1
CMD_SIGN = 1
DOMAIN_SUDO = 1

ROOT_KEY = bytes([
    0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23,
    0x30, 0x31, 0x32, 0x33, 0x40, 0x41, 0x42, 0x43,
    0x50, 0x51, 0x52, 0x53, 0x60, 0x61, 0x62, 0x63,
    0x70, 0x71, 0x72, 0x73, 0x80, 0x81, 0x82, 0x83
])

def derive_domain_key(root_key: bytes, domain: int) -> bytes:
    label = b"rp2350-token-domain:\x00" + bytes([domain])
    return hmac.new(root_key, label, hashlib.sha256).digest()

print("Enumerating devices:")
for d in hid.enumerate():
    if d["vendor_id"] == VID and d["product_id"] == PID:
        print("Found:", d)

challenge = os.urandom(32)

pkt = bytearray(64)
pkt[0] = REQ_VERSION
pkt[1] = CMD_SIGN
pkt[2] = DOMAIN_SUDO
pkt[3] = 0
pkt[4:36] = challenge

dev = hid.Device(VID, PID)
dev.write(b"\x00" + bytes(pkt))
resp = dev.read(64, timeout=2000)
dev.close()

resp = bytes(resp)

print("challenge :", challenge.hex())
print("response  :", resp.hex())

if len(resp) != 64:
    raise SystemExit("Bad response length")

version = resp[0]
status = resp[1]
domain = resp[2]
flags = resp[3]
mac = resp[4:36]

print("version   :", version)
print("status    :", status)
print("domain    :", domain)
print("flags     :", flags)
print("mac       :", mac.hex())

domain_key = derive_domain_key(ROOT_KEY, DOMAIN_SUDO)
expected = hmac.new(domain_key, bytes([REQ_VERSION, DOMAIN_SUDO]) + challenge, hashlib.sha256).digest()

print("expected  :", expected.hex())
print("match     :", mac == expected)
