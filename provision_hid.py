import argparse
import os
import hid

VID = 0xCAFE
PID = 0x4011

REQ_VERSION = 1
CMD_PROVISION = 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision RP2350 token master secret over HID."
    )
    parser.add_argument(
        "--secret-hex",
        default=None,
        help="32-byte master secret in hex (64 hex chars). If omitted, random is used.",
    )
    return parser.parse_args()


def get_secret_bytes(secret_hex: str | None) -> bytes:
    if secret_hex is None:
        return os.urandom(32)
    secret = bytes.fromhex(secret_hex)
    if len(secret) != 32:
        raise SystemExit("secret must be exactly 32 bytes (64 hex chars)")
    return secret


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


def main() -> None:
    args = parse_args()
    secret = get_secret_bytes(args.secret_hex)
    print("new_secret :", secret.hex())

    selected = select_token()

    pkt = bytearray(64)
    pkt[0] = REQ_VERSION
    pkt[1] = CMD_PROVISION
    pkt[2] = 0
    pkt[3] = 0
    pkt[4:36] = secret

    print("Press BOOTSEL within 3 seconds to approve provisioning...")
    dev = hid.Device(path=selected["path"])
    dev.write(b"\x00" + bytes(pkt))
    resp = bytes(dev.read(64, timeout=5000))
    dev.close()

    if len(resp) != 64:
        raise SystemExit("Bad response length")

    print("response   :", resp.hex())
    print("status     :", resp[1])
    print("applied    :", resp[4])

    if resp[1] != 0:
        raise SystemExit("Provisioning failed")


if __name__ == "__main__":
    main()
