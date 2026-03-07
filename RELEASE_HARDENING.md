# Release Hardening Plan

This document maps RP2350's native secure-boot features onto this repository and defines a practical release path for the current custom HID token.

## 1. What RP2350 supports natively

RP2350 already provides the core primitives needed for a hardened release build:

- Boot ROM signature verification for signed binaries.
- SHA-256 hashing and secp256k1 ECDSA signature verification during boot.
- 8 KB of OTP memory for boot configuration, signing-key hashes, and related policy.
- Anti-rollback support through versioned binaries.
- Optional encrypted boot for binaries stored in external flash.
- OTP permission controls that can limit what BOOTSEL mode and later software can read.

Official references:

- RP2350 secure-boot overview: <https://pip-assets.raspberrypi.com/categories/1260-security/documents/RP-009377-WP-1-Understanding%20RP2350_s%20security%20features.pdf>
- Pico SDK signing/encryption workflow: <https://datasheets.raspberrypi.com/pico/raspberry-pi-pico-c-sdk.pdf>
- RP2350 datasheet boot flows and secure boot: <https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf>
- RP2350 A4 stepping update: <https://www.raspberrypi.com/news/rp2350-a4-rp2354-and-a-new-hacking-challenge/>

## 2. Minimum hardware baseline

Use RP2350 A4 stepping or later for any release-grade secure-boot deployment.

Reason:

- Raspberry Pi fixed multiple boot ROM security issues in A4.
- Earlier public stepping should be treated as development-only for this project.

Operational rule:

- Development boards may remain unlocked.
- Release devices should be provisioned and OTP-locked only on A4-or-later silicon.

## 3. Recommended secure-boot architecture for this repo

The current token should stay a custom HID approval token for `sudo`, `ssh`, and `luks`-style flows. The secure-boot design should reinforce that model rather than replace it.

### 3.1 Build modes

Keep two explicit build classes:

- `dev`: current workflow, unsigned or test-signed, easy reflashing, no OTP lock assumptions.
- `release`: signed, versioned, provisioned, and OTP-locked according to the process below.

Recommended policy:

- Use different signing keys for `dev` and `release`.
- Never load the `dev` key hash into production OTP.

### 3.2 Image type

For release, prefer a signed packaged SRAM binary instead of executing secure code directly from flash.

Reason:

- Raspberry Pi's own security guidance recommends SRAM binaries because a flash-resident executable can be swapped after signature verification by a physical attacker.
- A packaged SRAM image is copied to SRAM and verified by the boot ROM before execution.

For this repo, that means:

- Code runs from SRAM in release builds.
- Persistent token state can still live in flash.
- The counter journal and provisioned secret remain flash-backed data, but executable code is not trusted in place from external flash.

### 3.3 Root of trust

The trust anchor should be a release signing public-key hash stored in OTP.

Recommended layout:

- one OTP key slot for the production signing key hash
- one separate key for development boards only
- OTP boot flags enabling secure boot only after validation on target hardware

Do not:

- reuse the same key for developer builds and field devices
- program production OTP from a workstation that also holds general development material

### 3.4 Update model

Release updates should be:

- signed with the same production private key
- monotonically versioned
- rejected if version is lower than the recorded rollback floor

This gives:

- authenticity
- integrity
- rollback resistance

### 3.5 Provisioning lifecycle

Provisioning should happen only after the device is on release firmware and secure boot is enabled.

Recommended sequence:

1. Flash signed release image.
2. Program OTP signing-key hash and secure-boot policy.
3. Reboot and verify signed boot succeeds.
4. Provision the token master secret.
5. Optionally set tighter OTP access limits for BOOTSEL/debug if your recovery model allows it.

This ordering matters because provisioning before secure boot leaves a gap where hostile firmware could still be loaded and exfiltrate the provisioned secret.

## 4. Practical repository changes for release mode

These are the repo-level changes that should exist before calling the design "release-hardened".

### 4.1 Build-system changes

Add a release build option that switches the target into a signed packaged SRAM image.

Target behavior:

- `pico_set_binary_type(rp2350_token no_flash)`
- `pico_package_uf2_output(rp2350_token 0x10000000)`
- `pico_sign_binary(rp2350_token /path/to/release-private.pem)`

Notes:

- The private key path should not be committed.
- CI can validate that release mode is wired correctly, but real signing keys should stay outside CI unless you use a controlled signing system.

### 4.2 Version policy

Introduce a firmware version variable that is treated as part of release metadata, not just a user-facing string.

Policy:

- every release increments the secure-boot version
- emergency rollback requires a deliberate signed recovery path, not ad hoc reflashing

### 4.3 Recovery policy

You need a recovery story before locking devices.

Pragmatic release policy:

- development boards remain recoverable and unlocked
- field devices accept only signed release firmware
- wipe should clear token state, but not secure-boot OTP policy

That distinction is important:

- wipe = erase local secret and counter state
- recovery = controlled reinstallation of newer trusted firmware

## 5. Suggested implementation phases

### Phase 1: Release build plumbing

Goal:

- add `RELEASE_SIGNING_KEY` and `RELEASE_BUILD` CMake options
- produce signed SRAM-packaged binaries
- keep current `build_beta` flow unchanged for development

Acceptance:

- release build emits signed artifacts and OTP JSON
- dev build still works exactly as today

### Phase 2: Versioned release policy

Goal:

- define a release version scheme compatible with RP2350 rollback protection
- document signing and upgrade procedure

Acceptance:

- release artifacts have explicit secure-boot versioning
- field update instructions reject downgrade-by-process

Implementation in this repo:

- `RELEASE_VERSION_MAJOR`
- `RELEASE_VERSION_MINOR`
- `RELEASE_ROLLBACK_VERSION`
- `RELEASE_ROLLBACK_ROWS`

Recommended version policy:

- increment `RELEASE_VERSION_MINOR` for normal compatible releases
- increment `RELEASE_VERSION_MAJOR` for intentionally incompatible release lines
- set `RELEASE_ROLLBACK_VERSION` to a monotonic floor that never decreases on fielded devices
- keep `RELEASE_ROLLBACK_ROWS` fixed for this product line once deployed
- choose rollback rows that satisfy the RP2350/picotool row-spacing rules; for `RBIT3`, a valid example is `100;103`

Operational rule:

- if a signed build has a lower rollback floor than the device expects, it must be treated as non-deployable even if the signature is valid

### Phase 3: Provision-after-secure-boot workflow

Goal:

- document and script a device bring-up sequence: flash signed image -> OTP enable -> verify boot -> provision secret

Acceptance:

- one operator can prepare a new board repeatably
- no secret is provisioned before the board is secure-boot locked

Implementation in this repo:

- `provision_release_device.sh`

Current scripted sequence:

1. `picotool load -f -x <signed uf2>`
2. `picotool otp load -f <otp json>`
3. `python3 get_state_hid.py`
4. `python3 provision_hid.py --secret-hex ...`

### Phase 4: Optional encrypted boot

Goal:

- evaluate encrypted SRAM boot for stronger code confidentiality and resistance to flash extraction

This is not the first release blocker. Signed boot is the priority. Encrypted boot is an additional hardening step.

## 6. Example release workflow

Example key generation:

```bash
openssl ecparam -name secp256k1 -genkey -out release-private.pem
openssl ec -in release-private.pem -pubout -out release-public.pem
```

Example release build shape:

```bash
cmake -S . -B build_release \
  -DRELEASE_BUILD=ON \
  -DRELEASE_SIGNING_KEY=$PWD/keys/release-private.pem \
  -DRELEASE_VERSION_MAJOR=1 \
  -DRELEASE_VERSION_MINOR=0 \
  -DRELEASE_ROLLBACK_VERSION=1 \
  -DRELEASE_ROLLBACK_ROWS="100;103"
cmake --build build_release -j
```

Expected release outputs:

- signed UF2 or packaged image
- OTP JSON generated by `pico_sign_binary()`

Per-device secure-boot enable step:

```bash
picotool otp load build_release/rp2350_token.otp.json
```

Suggested release operator flow:

1. choose the next release major/minor and rollback floor
2. build the signed release image with those values
3. verify the generated OTP JSON matches the intended key and rollback rows
4. flash the signed image to a sacrificial device
5. program OTP on that device
6. verify boot succeeds and older release images are no longer acceptable by policy
7. only then use the same release settings for field devices

Important:

- OTP programming is one-way in the ways that matter.
- Test the full process on sacrificial hardware before locking real devices.

## 7. Recommended next step for this repo

The next concrete implementation step should be Phase 1:

- add a `RELEASE_BUILD` CMake path
- add signing support
- keep the current development flow intact

That is the smallest useful secure-boot step because it turns the design from a discussion into a reproducible build artifact and forces the release/dev split to be explicit.
