import hashlib
import hmac
import os
import unittest

from host_protocol import (
    CMD_GET_STATE,
    CMD_PROVISION,
    CMD_SIGN,
    DOMAIN_SUDO,
    REQ_VERSION,
    SECURITY_MODE_BETA,
    SECURITY_MODE_STRICT,
    STATUS_NOT_PROVISIONED,
    STATUS_OK,
    STATUS_PROVISIONING_LOCKED,
    derive_device_root_key,
    derive_domain_key,
    parse_get_state_response,
)


class TokenSim:
    def __init__(self, uid_hex: str, flush_interval: int = 64):
        self.uid = bytes.fromhex(uid_hex)
        self.flush_interval = flush_interval
        self.persisted_counter = 0
        self.runtime_counter = 0
        self.generation = 0
        self.master_secret = None

    @property
    def security_mode(self) -> int:
        return SECURITY_MODE_STRICT if self.flush_interval <= 1 else SECURITY_MODE_BETA

    @property
    def provisioned(self) -> bool:
        return self.master_secret is not None

    def wipe(self) -> None:
        self.master_secret = None
        self.runtime_counter = 0
        self.persisted_counter = 0
        self.generation += 1

    def provision(self, master_secret: bytes) -> bytes:
        resp = bytearray(64)
        resp[0] = REQ_VERSION
        if self.provisioned:
            resp[1] = STATUS_PROVISIONING_LOCKED
            return bytes(resp)
        self.master_secret = master_secret
        self.generation += 1
        resp[1] = STATUS_OK
        resp[4] = 1
        return bytes(resp)

    def sign(self, challenge: bytes, domain: int = DOMAIN_SUDO) -> bytes:
        resp = bytearray(64)
        resp[0] = REQ_VERSION
        resp[2] = domain
        if not self.provisioned:
            resp[1] = STATUS_NOT_PROVISIONED
            return bytes(resp)

        self.runtime_counter += 1
        if (self.runtime_counter - self.persisted_counter) >= self.flush_interval:
            self.persisted_counter = self.runtime_counter
            self.generation += 1

        root_key = derive_device_root_key(self.master_secret, self.uid)
        domain_key = derive_domain_key(root_key, domain)
        msg = bytes([REQ_VERSION, domain]) + self.runtime_counter.to_bytes(4, "little") + challenge
        mac = hmac.new(domain_key, msg, hashlib.sha256).digest()
        resp[1] = STATUS_OK
        resp[4:36] = mac
        resp[36:40] = self.runtime_counter.to_bytes(4, "little")
        return bytes(resp)

    def get_state(self) -> bytes:
        resp = bytearray(64)
        resp[0] = REQ_VERSION
        resp[1] = STATUS_OK
        resp[4] = REQ_VERSION
        resp[5] = self.flush_interval
        flags = 0
        if self.provisioned:
            flags |= 0x01
            flags |= 0x04
        if self.runtime_counter != self.persisted_counter:
            flags |= 0x02
        resp[6] = flags
        resp[7] = self.security_mode
        resp[8:12] = self.runtime_counter.to_bytes(4, "little")
        resp[12:16] = self.persisted_counter.to_bytes(4, "little")
        resp[16:20] = self.generation.to_bytes(4, "little")
        resp[20:28] = self.uid
        return bytes(resp)


class ProtocolTests(unittest.TestCase):
    UID_HEX = "1C392206652CC650"
    SECRET_A = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    SECRET_B = bytes.fromhex("8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677")

    def test_unprovisioned_returns_status_7(self) -> None:
        token = TokenSim(self.UID_HEX)
        resp = token.sign(os.urandom(32))
        self.assertEqual(resp[1], STATUS_NOT_PROVISIONED)

    def test_provision_sign_get_state_beta(self) -> None:
        token = TokenSim(self.UID_HEX, flush_interval=64)
        self.assertEqual(token.provision(self.SECRET_A)[1], STATUS_OK)
        sign_resp = token.sign(os.urandom(32))
        self.assertEqual(sign_resp[1], STATUS_OK)
        state = parse_get_state_response(token.get_state())
        self.assertEqual(state["security_mode"], SECURITY_MODE_BETA)
        self.assertTrue(state["master_provisioned"])
        self.assertTrue(state["provisioning_locked"])
        self.assertEqual(state["runtime_counter"], 1)

    def test_wipe_returns_to_unprovisioned(self) -> None:
        token = TokenSim(self.UID_HEX)
        token.provision(self.SECRET_A)
        token.sign(os.urandom(32))
        token.wipe()
        state = parse_get_state_response(token.get_state())
        self.assertFalse(state["master_provisioned"])
        self.assertEqual(token.sign(os.urandom(32))[1], STATUS_NOT_PROVISIONED)

    def test_old_secret_fails_after_wipe_and_reprovision(self) -> None:
        token = TokenSim(self.UID_HEX)
        token.provision(self.SECRET_A)
        challenge = os.urandom(32)
        resp_old = token.sign(challenge)
        self.assertEqual(resp_old[1], STATUS_OK)

        token.wipe()
        self.assertEqual(token.provision(self.SECRET_B)[1], STATUS_OK)
        resp_new = token.sign(challenge)
        self.assertEqual(resp_new[1], STATUS_OK)

        root_old = derive_device_root_key(self.SECRET_A, bytes.fromhex(self.UID_HEX))
        domain_old = derive_domain_key(root_old, DOMAIN_SUDO)
        msg_new = bytes([REQ_VERSION, DOMAIN_SUDO]) + resp_new[36:40] + challenge
        old_mac = hmac.new(domain_old, msg_new, hashlib.sha256).digest()
        self.assertNotEqual(old_mac, resp_new[4:36])

    def test_strict_mode_reported(self) -> None:
        token = TokenSim(self.UID_HEX, flush_interval=1)
        token.provision(self.SECRET_A)
        token.sign(os.urandom(32))
        state = parse_get_state_response(token.get_state())
        self.assertEqual(state["security_mode"], SECURITY_MODE_STRICT)
        self.assertEqual(state["runtime_counter"], state["persisted_counter"])

    def test_reprovision_is_locked_until_wipe(self) -> None:
        token = TokenSim(self.UID_HEX)
        self.assertEqual(token.provision(self.SECRET_A)[1], STATUS_OK)
        self.assertEqual(token.provision(self.SECRET_B)[1], STATUS_PROVISIONING_LOCKED)


if __name__ == "__main__":
    unittest.main()
