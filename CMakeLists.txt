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

pico_add_extra_outputs(rp2350_token)
