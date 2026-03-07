#!/usr/bin/env bash
set -euo pipefail

# Provision a release-built RP2350 token in the intended order:
# 1. Flash signed release image
# 2. Program OTP secure-boot policy
# 3. Verify the token re-enumerates and answers GET_STATE
# 4. Provision the token secret over HID

BUILD_DIR="build_release"
SECRET_HEX=""
PYTHON_BIN="${PYTHON_BIN:-python3}"

usage() {
    cat <<'EOF'
Usage:
  provision_release_device.sh --secret-hex <64-hex> [--build-dir <dir>]

Options:
  --secret-hex   32-byte token secret in hex (required)
  --build-dir    Release build directory containing rp2350_token.uf2 and rp2350_token.otp.json

Example:
  ./provision_release_device.sh \
    --build-dir build_release \
    --secret-hex "$(openssl rand -hex 32)"
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --secret-hex)
            SECRET_HEX="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "$SECRET_HEX" ]]; then
    echo "--secret-hex is required" >&2
    usage >&2
    exit 1
fi

if [[ ! "$SECRET_HEX" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "secret must be exactly 64 hex characters" >&2
    exit 1
fi

UF2_PATH="$BUILD_DIR/rp2350_token.uf2"
OTP_JSON_PATH="$BUILD_DIR/rp2350_token.otp.json"

if [[ ! -f "$UF2_PATH" ]]; then
    echo "Missing signed UF2: $UF2_PATH" >&2
    exit 1
fi

if [[ ! -f "$OTP_JSON_PATH" ]]; then
    echo "Missing OTP JSON: $OTP_JSON_PATH" >&2
    exit 1
fi

echo "Release bring-up using:"
echo "  build dir : $BUILD_DIR"
echo "  uf2       : $UF2_PATH"
echo "  otp json  : $OTP_JSON_PATH"
echo "  secret    : $SECRET_HEX"
echo
echo "Step 1/4: flashing signed release image"
picotool load -f -x "$UF2_PATH"

echo
echo "Step 2/4: programming OTP secure-boot policy"
echo "This is intended for release devices. Review the generated OTP JSON before use."
picotool otp load -f "$OTP_JSON_PATH"

echo
echo "Step 3/4: verifying token responds after secure-boot setup"
sleep 2
"$PYTHON_BIN" get_state_hid.py

echo
echo "Step 4/4: provisioning token secret"
echo "Press BOOTSEL when the host tool asks for approval."
"$PYTHON_BIN" provision_hid.py --secret-hex "$SECRET_HEX"

echo
echo "Release provisioning complete."
echo "Verify signing with:"
echo "  $PYTHON_BIN test_hid.py --secret-hex $SECRET_HEX"
