import hashlib
import hmac

REQ_VERSION = 1

CMD_SIGN = 1
CMD_PROVISION = 2
CMD_GET_STATE = 3

DOMAIN_SUDO = 1
DOMAIN_SSH = 2
DOMAIN_LUKS = 3

STATUS_OK = 0
STATUS_BAD_VERSION = 1
STATUS_BAD_COMMAND = 2
STATUS_BAD_DOMAIN = 3
STATUS_USER_PRESENCE_REQUIRED = 4
STATUS_CRYPTO_ERROR = 5
STATUS_BAD_PAYLOAD = 6
STATUS_NOT_PROVISIONED = 7
STATUS_PROVISIONING_LOCKED = 8

SECURITY_MODE_STRICT = 1
SECURITY_MODE_BETA = 2


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


def parse_get_state_response(resp: bytes) -> dict:
    if len(resp) != 64:
        raise ValueError("response must be exactly 64 bytes")

    flags = resp[6]
    security_mode = resp[7]
    security_mode_name = {
        SECURITY_MODE_STRICT: "strict",
        SECURITY_MODE_BETA: "beta",
    }.get(security_mode, f"unknown({security_mode})")

    return {
        "status": resp[1],
        "protocol_version": resp[4],
        "flush_interval": resp[5],
        "flags": flags,
        "master_provisioned": bool(flags & 0x01),
        "counter_dirty_ram": bool(flags & 0x02),
        "provisioning_locked": bool(flags & 0x04),
        "security_mode": security_mode,
        "security_mode_name": security_mode_name,
        "runtime_counter": int.from_bytes(resp[8:12], "little"),
        "persisted_counter": int.from_bytes(resp[12:16], "little"),
        "state_generation": int.from_bytes(resp[16:20], "little"),
        "uid_hex": resp[20:28].hex().upper(),
    }
