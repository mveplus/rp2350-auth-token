cmake_minimum_required(VERSION 3.13)

set(PICO_PLATFORM rp2350)

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(rp2350_token C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(rp2350_token
    src/main.c
    src/usb_descriptors.c
    src/crypto.c
)

target_include_directories(rp2350_token PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
)

pico_generate_pio_header(rp2350_token ${CMAKE_CURRENT_LIST_DIR}/src/ws2812.pio)

target_link_libraries(rp2350_token
    pico_stdlib
    tinyusb_device
    tinyusb_board
    hardware_pio
)

pico_enable_stdio_usb(rp2350_token 0)
pico_enable_stdio_uart(rp2350_token 0)

pico_add_extra_outputs(rp2350_token)
