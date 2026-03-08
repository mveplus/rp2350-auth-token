# Third-Party Notices

This repository is licensed under the MIT License for original project code.

It also depends on third-party components that are separately licensed by their respective authors. The list below is a practical notice file for the main components used by this project.

## Raspberry Pi Pico SDK

- Project: Raspberry Pi Pico SDK
- Source: <https://github.com/raspberrypi/pico-sdk>
- License: BSD 3-Clause

This project builds against the Pico SDK and uses SDK-provided libraries, board support, boot tooling integration, and RP2350 build/signing support.

## TinyUSB

- Project: TinyUSB
- Source: <https://github.com/hathach/tinyusb>
- License: MIT

This project uses TinyUSB through the Pico SDK for USB HID device support.

## mbedTLS

- Project: Mbed TLS
- Source: <https://github.com/Mbed-TLS/mbedtls>
- License: Apache License 2.0

This project uses mbedTLS through the Pico SDK for HMAC-SHA256 and HKDF-based cryptographic operations.

## picotool

- Project: picotool
- Source: <https://github.com/raspberrypi/picotool>
- License: BSD 3-Clause

This project uses `picotool` for flashing, signing support in the Pico SDK build flow, and RP2350 OTP provisioning operations.

## Notes

- The `LICENSE` file in this repository applies to the original code in this repository, not to third-party dependencies.
- When redistributing source or binaries, review the upstream license terms for all bundled or linked components.
- For complete and authoritative license terms, consult each upstream project directly.
