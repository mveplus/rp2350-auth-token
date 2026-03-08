cmake_minimum_required(VERSION 3.13)

set(PICO_PLATFORM rp2350)

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(rp2350_token C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

# Optional board-agnostic LED pin overrides for WS2812 output.
set(WS2812_PIN_PRIMARY "" CACHE STRING "Primary WS2812 GPIO pin")
set(WS2812_PIN_SECONDARY "" CACHE STRING "Secondary WS2812 GPIO pin")
set(WS2812_PRIMARY_IS_GRB "" CACHE STRING "Primary WS2812 color order: 1=GRB, 0=RGB")
set(WS2812_SECONDARY_IS_GRB "" CACHE STRING "Secondary WS2812 color order: 1=GRB, 0=RGB")
set(COUNTER_FLUSH_INTERVAL "" CACHE STRING "Persist counter every N signatures")
set(APPROVAL_TIMEOUT_MS "" CACHE STRING "User-presence approval window in milliseconds")
set(WIPE_HOLD_MS "" CACHE STRING "Hold BOOTSEL during boot for this many ms to wipe provisioned state")
set(SECRET_WRAP_OTP_ROW_START "" CACHE STRING "OTP row start for 8 ECC rows of flash-wrapping secret material")
set(ALLOW_INSECURE_STORAGE_FALLBACK "" CACHE STRING "Allow plaintext secret storage fallback when no OTP wrap secret is configured (1=yes, 0=no)")
option(RELEASE_BUILD "Build a signed RP2350 release image for secure boot" OFF)
set(RELEASE_SIGNING_KEY "" CACHE FILEPATH "PEM private key used by pico_sign_binary() for release builds")
set(RELEASE_UF2_PACKAGE_ADDR "0x10000000" CACHE STRING "UF2 package address for release no-flash images")
set(RELEASE_OTP_JSON "" CACHE FILEPATH "Optional custom output path for generated release OTP JSON")
set(RELEASE_VERSION_MAJOR "" CACHE STRING "Secure-boot major version for release builds")
set(RELEASE_VERSION_MINOR "" CACHE STRING "Secure-boot minor version for release builds")
set(RELEASE_ROLLBACK_VERSION "" CACHE STRING "Secure-boot rollback floor for release builds")
set(RELEASE_ROLLBACK_ROWS "" CACHE STRING "Semicolon-separated OTP rows used for rollback tracking in release builds")

add_executable(rp2350_token
    src/main.c
    src/usb_descriptors.c
    src/crypto.c
)

target_include_directories(rp2350_token PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
)

if (NOT "${WS2812_PIN_PRIMARY}" STREQUAL "")
    target_compile_definitions(rp2350_token PRIVATE WS2812_PIN_PRIMARY=${WS2812_PIN_PRIMARY})
endif()

if (NOT "${WS2812_PIN_SECONDARY}" STREQUAL "")
    target_compile_definitions(rp2350_token PRIVATE WS2812_PIN_SECONDARY=${WS2812_PIN_SECONDARY})
endif()

if (NOT "${WS2812_PRIMARY_IS_GRB}" STREQUAL "")
    target_compile_definitions(rp2350_token PRIVATE WS2812_PRIMARY_IS_GRB=${WS2812_PRIMARY_IS_GRB})
endif()

if (NOT "${WS2812_SECONDARY_IS_GRB}" STREQUAL "")
    target_compile_definitions(rp2350_token PRIVATE WS2812_SECONDARY_IS_GRB=${WS2812_SECONDARY_IS_GRB})
endif()

if (NOT "${COUNTER_FLUSH_INTERVAL}" STREQUAL "")
    target_compile_definitions(rp2350_token PRIVATE COUNTER_FLUSH_INTERVAL=${COUNTER_FLUSH_INTERVAL})
endif()

if (NOT "${APPROVAL_TIMEOUT_MS}" STREQUAL "")
    target_compile_definitions(rp2350_token PRIVATE APPROVAL_TIMEOUT_MS=${APPROVAL_TIMEOUT_MS})
endif()

if (NOT "${WIPE_HOLD_MS}" STREQUAL "")
    target_compile_definitions(rp2350_token PRIVATE WIPE_HOLD_MS=${WIPE_HOLD_MS})
endif()

if (NOT "${SECRET_WRAP_OTP_ROW_START}" STREQUAL "")
    target_compile_definitions(rp2350_token PRIVATE SECRET_WRAP_OTP_ROW_START=${SECRET_WRAP_OTP_ROW_START})
endif()

if (NOT "${ALLOW_INSECURE_STORAGE_FALLBACK}" STREQUAL "")
    target_compile_definitions(rp2350_token PRIVATE ALLOW_INSECURE_STORAGE_FALLBACK=${ALLOW_INSECURE_STORAGE_FALLBACK})
endif()

pico_generate_pio_header(rp2350_token ${CMAKE_CURRENT_LIST_DIR}/src/ws2812.pio)

target_link_libraries(rp2350_token
    pico_stdlib
    tinyusb_device
    tinyusb_board
    hardware_pio
    pico_unique_id
    pico_mbedtls
)

pico_enable_stdio_usb(rp2350_token 0)
pico_enable_stdio_uart(rp2350_token 0)

if (RELEASE_BUILD)
    if ("${RELEASE_SIGNING_KEY}" STREQUAL "")
        message(FATAL_ERROR "RELEASE_BUILD=ON requires -DRELEASE_SIGNING_KEY=/path/to/release-private.pem")
    endif()
    if ("${RELEASE_VERSION_MAJOR}" STREQUAL "" OR "${RELEASE_VERSION_MINOR}" STREQUAL "" OR
        "${RELEASE_ROLLBACK_VERSION}" STREQUAL "" OR "${RELEASE_ROLLBACK_ROWS}" STREQUAL "")
        message(FATAL_ERROR
            "RELEASE_BUILD=ON requires RELEASE_VERSION_MAJOR, RELEASE_VERSION_MINOR, "
            "RELEASE_ROLLBACK_VERSION and RELEASE_ROLLBACK_ROWS")
    endif()

    # Release builds execute from SRAM after boot ROM verification instead of trusting
    # executable code directly from external flash.
    pico_set_binary_type(rp2350_token no_flash)
    pico_package_uf2_output(rp2350_token ${RELEASE_UF2_PACKAGE_ADDR})
    pico_set_binary_version(rp2350_token
        MAJOR ${RELEASE_VERSION_MAJOR}
        MINOR ${RELEASE_VERSION_MINOR}
        ROLLBACK ${RELEASE_ROLLBACK_VERSION}
        ROWS ${RELEASE_ROLLBACK_ROWS}
    )

    if (NOT "${RELEASE_OTP_JSON}" STREQUAL "")
        pico_set_otp_key_output_file(rp2350_token ${RELEASE_OTP_JSON})
    endif()

    pico_sign_binary(rp2350_token ${RELEASE_SIGNING_KEY})
    target_compile_definitions(rp2350_token PRIVATE RELEASE_BUILD=1)
endif()

pico_add_extra_outputs(rp2350_token)
