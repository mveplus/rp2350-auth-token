import argparse
import hashlib
import hmac
import os
import time
import hid

VID = 0xCAFE
PID = 0x4011

REQ_VERSION = 1
CMD_SIGN = 1
CMD_PROVISION = 2
CMD_GET_STATE = 3
DOMAIN_SUDO = 1

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, out_len: int) -> bytes:
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


def select_token() -> dict:
    selected = None
    for d in hid.enumerate():
        if d["vendor_id"] == VID and d["product_id"] == PID:
            print("Found:", d)
            if selected is None:
                selected = d
    if selected is None:
        raise SystemExit("Token not found")
    return selected


def send_packet(path: bytes, pkt: bytes, timeout_ms: int = 6000) -> bytes:
    dev = hid.Device(path=path)
    dev.write(b"\x00" + pkt)
    resp = bytes(dev.read(64, timeout=timeout_ms))
    dev.close()
    if len(resp) != 64:
        raise SystemExit("Bad response length")
    return resp


def do_sign(path: bytes, master_secret: bytes, uid_bytes: bytes) -> tuple[int, bytes]:
    challenge = os.urandom(32)
    pkt = bytearray(64)
    pkt[0] = REQ_VERSION
    pkt[1] = CMD_SIGN
    pkt[2] = DOMAIN_SUDO
    pkt[3] = 0
    pkt[4:36] = challenge

    print("Press BOOTSEL to approve sign request...")
    resp = send_packet(path, bytes(pkt))
    if resp[1] != 0:
        raise SystemExit(f"SIGN failed with status={resp[1]}")

    mac = resp[4:36]
    counter = int.from_bytes(resp[36:40], "little")

    device_root_key = derive_device_root_key(master_secret, uid_bytes)
    domain_key = derive_domain_key(device_root_key, DOMAIN_SUDO)
    signed_msg = bytes([REQ_VERSION, DOMAIN_SUDO]) + counter.to_bytes(4, "little") + challenge
    expected = hmac.new(domain_key, signed_msg, hashlib.sha256).digest()
    if mac != expected:
        raise SystemExit("MAC mismatch")

    print(f"SIGN ok counter={counter}")
    return counter, challenge


def do_provision(path: bytes, new_secret: bytes) -> None:
    pkt = bytearray(64)
    pkt[0] = REQ_VERSION
    pkt[1] = CMD_PROVISION
    pkt[2] = 0
    pkt[3] = 0
    pkt[4:36] = new_secret

    print("Press BOOTSEL to approve provisioning...")
    resp = send_packet(path, bytes(pkt))
    if resp[1] != 0:
        raise SystemExit(f"PROVISION failed with status={resp[1]}")
    if resp[4] != 1:
        raise SystemExit("PROVISION response missing applied marker")
    print("PROVISION ok")


def get_state(path: bytes) -> tuple[int, int]:
    pkt = bytearray(64)
    pkt[0] = REQ_VERSION
    pkt[1] = CMD_GET_STATE
    resp = send_packet(path, bytes(pkt), timeout_ms=3000)
    if resp[1] != 0:
        raise SystemExit(f"GET_STATE failed with status={resp[1]}")
    runtime_counter = int.from_bytes(resp[8:12], "little")
    persisted_counter = int.from_bytes(resp[12:16], "little")
    return runtime_counter, persisted_counter


def main() -> None:
    parser = argparse.ArgumentParser(description="Run host regression checks against RP2350 token.")
    parser.add_argument(
        "--initial-secret-hex",
        required=True,
        help="Secret currently active before test starts.",
    )
    parser.add_argument(
        "--new-secret-hex",
        default="8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
        help="Secret to provision during test.",
    )
    args = parser.parse_args()

    initial_secret = bytes.fromhex(args.initial_secret_hex)
    new_secret = bytes.fromhex(args.new_secret_hex)
    if len(initial_secret) != 32 or len(new_secret) != 32:
        raise SystemExit("Both secrets must be exactly 32 bytes (64 hex chars)")

    selected = select_token()
    path = selected["path"]
    serial = selected.get("serial_number", "")
    uid_bytes = bytes.fromhex(serial)
    print("Using serial:", serial)

    print("\n[1/5] Baseline SIGN #1")
    counter1, _ = do_sign(path, initial_secret, uid_bytes)

    print("\n[2/5] Baseline SIGN #2")
    counter2, _ = do_sign(path, initial_secret, uid_bytes)
    if counter2 != counter1 + 1:
        raise SystemExit(f"Counter did not increment by 1 ({counter1} -> {counter2})")

    print("\n[3/5] PROVISION new secret")
    do_provision(path, new_secret)
    time.sleep(0.2)

    print("\n[4/5] SIGN should fail verification with old secret")
    challenge = os.urandom(32)
    pkt = bytearray(64)
    pkt[0] = REQ_VERSION
    pkt[1] = CMD_SIGN
    pkt[2] = DOMAIN_SUDO
    pkt[4:36] = challenge
    print("Press BOOTSEL to approve sign request...")
    resp = send_packet(path, bytes(pkt))
    if resp[1] != 0:
        raise SystemExit(f"SIGN failed with status={resp[1]}")
    old_root = derive_device_root_key(initial_secret, uid_bytes)
    old_domain = derive_domain_key(old_root, DOMAIN_SUDO)
    c_old = int.from_bytes(resp[36:40], "little")
    expected_old = hmac.new(old_domain, bytes([REQ_VERSION, DOMAIN_SUDO]) + c_old.to_bytes(4, "little") + challenge, hashlib.sha256).digest()
    if expected_old == resp[4:36]:
        raise SystemExit("Old secret unexpectedly still validates after provisioning")
    print("Old secret correctly rejected")

    print("\n[5/5] SIGN with new secret + state query")
    counter3, _ = do_sign(path, new_secret, uid_bytes)
    runtime_counter, persisted_counter = get_state(path)
    print("GET_STATE runtime_counter :", runtime_counter)
    print("GET_STATE persisted_counter:", persisted_counter)
    if runtime_counter < counter3:
        raise SystemExit("GET_STATE runtime counter is behind last signature")

    print("\nRegression passed")


if __name__ == "__main__":
    main()
