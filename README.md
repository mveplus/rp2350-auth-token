# Marto RP2350 HID Token

USB HID security token prototype for RP2350.

## Current capabilities

- Custom USB HID transport
- mbedTLS-backed HMAC-SHA256 challenge/response
- mbedTLS-backed HKDF per-device root key derivation
- Per-domain key derivation from per-device root key
- BOOTSEL user-presence approval
- 3-second approval window
- WS2812 LED state feedback
- Monotonic counter included in signed payload with flash checkpoint batching
- Device UID exposed as USB serial for deterministic host-side verification
- HID provisioning command for replacing the master secret
- HID state command (`CMD_GET_STATE=3`) for diagnostics
- Dual WS2812 pin compatibility output (GPIO22 + GPIO16) for mixed RP2350 mini boards

## Security notes

- Demo master secret remains in source for easy testing.
- Provisioning command can replace it with a flash-persisted secret.
- Dual-slot flash state stores counter checkpoint + provisioned secret with CRC and generation.
- Counter wear mitigation uses `COUNTER_FLUSH_INTERVAL` (default `64`) to checkpoint every N signatures.
- Tradeoff: abrupt power loss can roll back up to `COUNTER_FLUSH_INTERVAL - 1` unsaved counter steps.

## LED compatibility

The firmware drives WS2812 on both a primary and compatibility pin in one image:

- Primary: `PICO_DEFAULT_WS2812_PIN` (if board header defines it), else GPIO22.
- Secondary compatibility pin: GPIO16.
- Color order defaults:
  - Primary: GRB (`WS2812_PRIMARY_IS_GRB=1`)
  - Secondary: RGB (`WS2812_SECONDARY_IS_GRB=0`) to match Waveshare RP2350 Zero behavior.

You can override these at compile time with:

```bash
cmake -S . -B build_beta \
  -DWS2812_PIN_PRIMARY=<pin> \
  -DWS2812_PIN_SECONDARY=<pin> \
  -DWS2812_PRIMARY_IS_GRB=<0|1> \
  -DWS2812_SECONDARY_IS_GRB=<0|1>
```

## Architecture

```text
Linux host
   |
   | 64-byte HID request
   v
RP2350 HID Token
   |
   +-- Request parser
   +-- BOOTSEL approval window
   +-- LED state machine
   +-- UID-based root key derivation (HKDF)
   +-- Per-domain key derivation
  +-- HMAC-SHA256 (mbedTLS)
   +-- Monotonic runtime counter
   +-- Dual-slot flash state (counter checkpoint + provisioned secret)
   +-- GET_STATE diagnostics command
   +-- Device UID as serial descriptor
   |
   v
64-byte HID response

## Scripts

- `test_hid.py`: sends sign command and verifies MAC.
- `provision_hid.py`: sends provisioning command (`CMD_PROVISION=2`) with a 32-byte secret in payload bytes `[4..35]`.
- `get_state_hid.py`: queries `CMD_GET_STATE=3` and prints counters/checkpoint/generation/UID.
- `regression_hid.py`: automated sign/provision/sign regression flow.

## Build and flash

```bash
cmake -S . -B build_beta
cmake --build build_beta -j
```

Optional flash-wear tuning:

```bash
cmake -S . -B build_beta -DCOUNTER_FLUSH_INTERVAL=64
```

If the board is in BOOTSEL mode and mounted as a USB mass-storage device:

```bash
cp build_beta/rp2350_token.uf2 /run/media/$USER/RP2350/
sync
```

## Verified test flow

On some Linux setups, HID raw device access requires `sudo`.

1. Run sign test with demo secret:
```bash
sudo python3 test_hid.py
```
Expected: `status : 0` and `match : True`.

2. Provision a new master secret (press BOOTSEL when prompted):
```bash
sudo python3 provision_hid.py --secret-hex 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

3. Update one line in `test_hid.py`:
```python
MASTER_SECRET = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
```

4. Re-run sign test:
```bash
sudo python3 test_hid.py
```
Expected: `status : 0` and `match : True`.

5. Query device state:
```bash
sudo python3 get_state_hid.py
```

6. Run full regression:
```bash
sudo python3 regression_hid.py
```

## Testing another board

Repeat flash + sign test on the second board. The serial number should differ, and derived keys will be unique per board UID.

Recommended sequence:

1. Put second board in BOOTSEL and flash `build_beta/rp2350_token.uf2`.
2. Run `sudo python3 test_hid.py` and verify `match : True`.
3. Optionally provision a different secret using `provision_hid.py` and re-test.

## Linux udev (no sudo)

Install included rule and reload udev:

```bash
./install_udev_rule.sh
```

Then replug the token and run scripts without `sudo`.
