#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "bsp/board.h"
#include "tusb.h"
#include "crypto.h"

#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"

#include "ws2812.pio.h"

#define WS2812_PIN 22
#define IS_RGBW false

static uint8_t rx_buf[64];
static volatile bool packet_received = false;

// TEST ONLY - replace later with provisioned secret in flash
static const uint8_t root_key[32] = {
    0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23,
    0x30, 0x31, 0x32, 0x33, 0x40, 0x41, 0x42, 0x43,
    0x50, 0x51, 0x52, 0x53, 0x60, 0x61, 0x62, 0x63,
    0x70, 0x71, 0x72, 0x73, 0x80, 0x81, 0x82, 0x83
};

enum {
    REQ_VERSION = 1,
    CMD_SIGN = 1,
};

enum {
    DOMAIN_SUDO = 1,
    DOMAIN_SSH  = 2,
    DOMAIN_LUKS = 3,
};

enum {
    STATUS_OK = 0,
    STATUS_BAD_VERSION = 1,
    STATUS_BAD_COMMAND = 2,
    STATUS_BAD_DOMAIN  = 3,
    STATUS_USER_PRESENCE_REQUIRED = 4,
};

static PIO ws2812_pio = pio0;
static int ws2812_sm = 0;

// ----------------------------------------------------------------------------
// WS2812 helpers
// ----------------------------------------------------------------------------

static inline void put_pixel(uint32_t pixel_grb) {
    pio_sm_put_blocking(ws2812_pio, ws2812_sm, pixel_grb << 8u);
}

static inline uint32_t urgb_u32(uint8_t r, uint8_t g, uint8_t b) {
    return ((uint32_t)g << 16) | ((uint32_t)r << 8) | (uint32_t)b;
}

static inline void ws2812_program_init_local(PIO pio, uint sm, uint offset, uint pin, float freq, bool rgbw) {
    pio_gpio_init(pio, pin);
    pio_sm_set_consecutive_pindirs(pio, sm, pin, 1, true);

    pio_sm_config c = ws2812_program_get_default_config(offset);
    sm_config_set_sideset_pins(&c, pin);
    sm_config_set_out_shift(&c, false, true, rgbw ? 32 : 24);
    sm_config_set_fifo_join(&c, PIO_FIFO_JOIN_TX);

    int cycles_per_bit = ws2812_T1 + ws2812_T2 + ws2812_T3;
    float div = (float)clock_get_hz(clk_sys) / (freq * cycles_per_bit);
    sm_config_set_clkdiv(&c, div);

    pio_sm_init(pio, sm, offset, &c);
    pio_sm_set_enabled(pio, sm, true);
}

static void ws2812_init_led(void) {
    uint offset = pio_add_program(ws2812_pio, &ws2812_program);
    ws2812_program_init_local(ws2812_pio, ws2812_sm, offset, WS2812_PIN, 800000, IS_RGBW);
}

static void led_set_rgb(uint8_t r, uint8_t g, uint8_t b) {
    put_pixel(urgb_u32(r, g, b));
}

// ----------------------------------------------------------------------------
// BOOTSEL button read
// ----------------------------------------------------------------------------

bool __no_inline_not_in_flash_func(get_bootsel_button_local)(void) {
    const uint CS_PIN_INDEX = 1;
    uint32_t flags = save_and_disable_interrupts();

    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
        GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
        IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    for (volatile int i = 0; i < 1000; ++i) { }

#if PICO_RP2040
    #define CS_BIT (1u << 1)
#else
    #define CS_BIT SIO_GPIO_HI_IN_QSPI_CSN_BITS
#endif

    bool button_pressed = !(sio_hw->gpio_hi_in & CS_BIT);

    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
        GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
        IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    restore_interrupts(flags);
    return button_pressed;
}

// ----------------------------------------------------------------------------
// TinyUSB callbacks
// ----------------------------------------------------------------------------

void tud_mount_cb(void) {}
void tud_umount_cb(void) {}
void tud_suspend_cb(bool remote_wakeup_en) { (void)remote_wakeup_en; }
void tud_resume_cb(void) {}

uint16_t tud_hid_get_report_cb(uint8_t instance,
                               uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t* buffer,
                               uint16_t reqlen) {
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)reqlen;
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance,
                           uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const* buffer,
                           uint16_t bufsize) {
    (void)instance;
    (void)report_id;
    (void)report_type;

    memset(rx_buf, 0, sizeof(rx_buf));
    if (bufsize > sizeof(rx_buf)) bufsize = sizeof(rx_buf);
    memcpy(rx_buf, buffer, bufsize);
    packet_received = true;
}

// ----------------------------------------------------------------------------
// Token logic
// ----------------------------------------------------------------------------

static void process_packet(uint8_t tx[64]) {
    memset(tx, 0, 64);

    uint8_t version = rx_buf[0];
    uint8_t command = rx_buf[1];
    uint8_t domain  = rx_buf[2];
    uint8_t flags   = rx_buf[3];

    tx[0] = version;
    tx[1] = STATUS_OK;
    tx[2] = domain;
    tx[3] = flags;

    if (version != REQ_VERSION) {
        tx[1] = STATUS_BAD_VERSION;
        return;
    }

    if (command != CMD_SIGN) {
        tx[1] = STATUS_BAD_COMMAND;
        return;
    }

    if (domain < DOMAIN_SUDO || domain > DOMAIN_LUKS) {
        tx[1] = STATUS_BAD_DOMAIN;
        return;
    }

    // Approval window: 3 seconds
    absolute_time_t deadline = make_timeout_time_ms(3000);
    bool approved = false;
    bool blink_on = false;
    absolute_time_t last_blink = get_absolute_time();

    while (absolute_time_diff_us(get_absolute_time(), deadline) > 0) {
        tud_task();

        if (get_bootsel_button_local()) {
            approved = true;
            break;
        }

        // Blue blink while waiting for approval
        if (absolute_time_diff_us(last_blink, get_absolute_time()) >= 150000) {
            last_blink = get_absolute_time();
            blink_on = !blink_on;

            if (blink_on) {
                led_set_rgb(0, 0, 32);
            } else {
                led_set_rgb(0, 0, 0);
            }
        }
    }

    if (!approved) {
        tx[1] = STATUS_USER_PRESENCE_REQUIRED;

        // Yellow flash = denied / timeout
        led_set_rgb(32, 32, 0);
        sleep_ms(120);
        led_set_rgb(0, 0, 0);
        return;
    }

    // Red flash while approving
    led_set_rgb(32, 0, 0);
    sleep_ms(80);

    uint8_t domain_key[32];
    uint8_t msg[34];
    uint8_t mac[32];

    derive_domain_key(root_key, domain, domain_key);

    msg[0] = version;
    msg[1] = domain;
    memcpy(&msg[2], &rx_buf[4], 32);

    hmac_sha256(domain_key, sizeof(domain_key), msg, sizeof(msg), mac);
    memcpy(&tx[4], mac, 32);

    // White flash = success
    led_set_rgb(32, 32, 32);
    sleep_ms(120);
    led_set_rgb(0, 0, 0);
}

// ----------------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------------
int main(void) {
    board_init();
    tusb_init();
    ws2812_init_led();

    absolute_time_t last_blink = get_absolute_time();
    bool blink_on = false;

    while (1) {
        tud_task();

        // Only show idle green blink when no packet is being processed
        if (!packet_received &&
            absolute_time_diff_us(last_blink, get_absolute_time()) >= 250000) {
            last_blink = get_absolute_time();
            blink_on = !blink_on;

            if (blink_on) {
                led_set_rgb(0, 32, 0);
            } else {
                led_set_rgb(0, 0, 0);
            }
        }

        if (packet_received && tud_hid_ready()) {
            uint8_t tx[64];
            process_packet(tx);
            tud_hid_report(0, tx, sizeof(tx));
            packet_received = false;
        }
    }
}
