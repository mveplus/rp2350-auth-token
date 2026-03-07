#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bsp/board.h"
#include "tusb.h"
#include "crypto.h"

#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "hardware/flash.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#include "hardware/regs/addressmap.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"

#include "ws2812.pio.h"

#define IS_RGBW false

// LED pin strategy:
// - Primary pin: board default WS2812 pin when available, else legacy pin 22.
// - Secondary pin: optional compatibility pin 16 for Waveshare RP2350 Zero family.
// This lets one firmware image drive either board's RGB LED.
#ifndef WS2812_PIN_PRIMARY
#if defined(PICO_DEFAULT_WS2812_PIN)
#define WS2812_PIN_PRIMARY PICO_DEFAULT_WS2812_PIN
#else
#define WS2812_PIN_PRIMARY 22
#endif
#endif

#ifndef WS2812_PIN_SECONDARY
#define WS2812_PIN_SECONDARY 16
#endif

// Channel order per output pin:
// 1 = GRB (most common WS2812 order), 0 = RGB.
// Tenstar board on GPIO22 expects GRB; Waveshare Zero on GPIO16 reports RGB.
#ifndef WS2812_PRIMARY_IS_GRB
#define WS2812_PRIMARY_IS_GRB 1
#endif

#ifndef WS2812_SECONDARY_IS_GRB
#define WS2812_SECONDARY_IS_GRB 0
#endif

static uint8_t rx_buf[64];
static volatile uint16_t rx_len = 0;
static volatile bool packet_received = false;

// Demo provisioning secret. In production, inject this during provisioning
// and never keep it in source control.
static const uint8_t demo_master_secret[32] = {
    0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23,
    0x30, 0x31, 0x32, 0x33, 0x40, 0x41, 0x42, 0x43,
    0x50, 0x51, 0x52, 0x53, 0x60, 0x61, 0x62, 0x63,
    0x70, 0x71, 0x72, 0x73, 0x80, 0x81, 0x82, 0x83
};

static uint8_t device_root_key[32];
static uint8_t active_master_secret[32];
static pico_unique_board_id_t device_uid;
static bool crypto_ready = false;

enum {
    REQ_VERSION = 1,
    CMD_SIGN = 1,
    CMD_PROVISION = 2,
    CMD_GET_STATE = 3,
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
    STATUS_CRYPTO_ERROR = 5,
    STATUS_BAD_PAYLOAD = 6,
};

static PIO ws2812_pio = pio0;
static int ws2812_sm_primary = 0;
static int ws2812_sm_secondary = 1;
static bool ws2812_secondary_enabled = false;

// ----------------------------------------------------------------------------
// Persistent token state (dual-slot flash journal)
// ----------------------------------------------------------------------------

#define TOKEN_STATE_MAGIC             0x314e4b54u // "TKN1"
#define TOKEN_STATE_VERSION           1u
#define TOKEN_FLAG_MASTER_SECRET_SET  0x0001u

#define TOKEN_STATE_SLOT_A_OFFSET (PICO_FLASH_SIZE_BYTES - (2 * FLASH_SECTOR_SIZE))
#define TOKEN_STATE_SLOT_B_OFFSET (PICO_FLASH_SIZE_BYTES - (1 * FLASH_SECTOR_SIZE))

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t generation;
    uint32_t counter;
    uint8_t provisioned_master_secret[32];
    uint32_t crc32;
} token_state_t;

static token_state_t token_state;
static int active_state_slot = -1;
static uint32_t runtime_counter = 0;

// Wear mitigation: checkpoint counter to flash every N signatures.
#ifndef COUNTER_FLUSH_INTERVAL
#define COUNTER_FLUSH_INTERVAL 64u
#endif

#ifndef APPROVAL_TIMEOUT_MS
#define APPROVAL_TIMEOUT_MS 3000u
#endif

static uint32_t crc32_update(uint32_t crc, uint8_t byte) {
    crc ^= byte;
    for (int i = 0; i < 8; ++i) {
        crc = (crc & 1u) ? ((crc >> 1) ^ 0xedb88320u) : (crc >> 1);
    }
    return crc;
}

static uint32_t crc32_compute(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < len; ++i) {
        crc = crc32_update(crc, p[i]);
    }
    return ~crc;
}

static bool token_state_is_valid(const token_state_t *state) {
    if (state->magic != TOKEN_STATE_MAGIC || state->version != TOKEN_STATE_VERSION) {
        return false;
    }
    uint32_t expected = crc32_compute(state, offsetof(token_state_t, crc32));
    return expected == state->crc32;
}

static bool read_state_slot(int slot, token_state_t *out) {
    uint32_t offset = (slot == 0) ? TOKEN_STATE_SLOT_A_OFFSET : TOKEN_STATE_SLOT_B_OFFSET;
    const uint8_t *flash_ptr = (const uint8_t *)(XIP_BASE + offset);
    memcpy(out, flash_ptr, sizeof(*out));
    return token_state_is_valid(out);
}

static bool write_state_slot(int slot, const token_state_t *state) {
    uint32_t offset = (slot == 0) ? TOKEN_STATE_SLOT_A_OFFSET : TOKEN_STATE_SLOT_B_OFFSET;
    uint8_t page[FLASH_PAGE_SIZE];
    memset(page, 0xff, sizeof(page));
    memcpy(page, state, sizeof(*state));

    uint32_t flags = save_and_disable_interrupts();
    flash_range_erase(offset, FLASH_SECTOR_SIZE);
    flash_range_program(offset, page, FLASH_PAGE_SIZE);
    restore_interrupts(flags);

    token_state_t verify;
    return read_state_slot(slot, &verify);
}

static void select_active_master_secret(void) {
    if (token_state.flags & TOKEN_FLAG_MASTER_SECRET_SET) {
        memcpy(active_master_secret, token_state.provisioned_master_secret, sizeof(active_master_secret));
    } else {
        memcpy(active_master_secret, demo_master_secret, sizeof(active_master_secret));
    }
}

static void load_token_state(void) {
    token_state_t slot_a = {0};
    token_state_t slot_b = {0};
    bool a_valid = read_state_slot(0, &slot_a);
    bool b_valid = read_state_slot(1, &slot_b);

    if (a_valid && b_valid) {
        if (slot_b.generation > slot_a.generation) {
            token_state = slot_b;
            active_state_slot = 1;
        } else {
            token_state = slot_a;
            active_state_slot = 0;
        }
    } else if (a_valid) {
        token_state = slot_a;
        active_state_slot = 0;
    } else if (b_valid) {
        token_state = slot_b;
        active_state_slot = 1;
    } else {
        memset(&token_state, 0, sizeof(token_state));
        token_state.magic = TOKEN_STATE_MAGIC;
        token_state.version = TOKEN_STATE_VERSION;
        active_state_slot = -1;
    }

    select_active_master_secret();
    runtime_counter = token_state.counter;
}

static bool persist_token_state(uint32_t new_counter,
                                const uint8_t *new_master_secret,
                                bool set_master_secret) {
    token_state_t next = token_state;

    next.magic = TOKEN_STATE_MAGIC;
    next.version = TOKEN_STATE_VERSION;
    next.generation = token_state.generation + 1;
    next.counter = new_counter;

    if (set_master_secret && new_master_secret) {
        memcpy(next.provisioned_master_secret, new_master_secret, sizeof(next.provisioned_master_secret));
        next.flags |= TOKEN_FLAG_MASTER_SECRET_SET;
    }

    next.crc32 = crc32_compute(&next, offsetof(token_state_t, crc32));

    int target_slot = (active_state_slot == 0) ? 1 : 0;
    if (!write_state_slot(target_slot, &next)) {
        return false;
    }

    token_state = next;
    active_state_slot = target_slot;
    select_active_master_secret();
    return true;
}

static void recompute_device_root_key(void) {
    // Device key is deterministic for this board UID and currently selected master secret.
    crypto_ready = derive_device_root_key(active_master_secret, sizeof(active_master_secret),
                                          device_uid.id, sizeof(device_uid.id),
                                          device_root_key);
}

static bool flush_counter_checkpoint_if_needed(uint32_t next_counter) {
    if (next_counter < token_state.counter) {
        return false;
    }

    if ((next_counter - token_state.counter) < COUNTER_FLUSH_INTERVAL) {
        return true;
    }

    return persist_token_state(next_counter, NULL, false);
}

// ----------------------------------------------------------------------------
// WS2812 helpers
// ----------------------------------------------------------------------------

static inline uint32_t pack_color(uint8_t r, uint8_t g, uint8_t b, bool is_grb) {
    if (is_grb) {
        return ((uint32_t)g << 16) | ((uint32_t)r << 8) | (uint32_t)b;
    }
    return ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

static inline void put_pixel(uint32_t pixel_primary, uint32_t pixel_secondary) {
    pio_sm_put_blocking(ws2812_pio, ws2812_sm_primary, pixel_primary << 8u);
    if (ws2812_secondary_enabled) {
        pio_sm_put_blocking(ws2812_pio, ws2812_sm_secondary, pixel_secondary << 8u);
    }
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
    ws2812_program_init_local(ws2812_pio, ws2812_sm_primary, offset, WS2812_PIN_PRIMARY, 800000, IS_RGBW);

    // Optional second output for boards that wire WS2812 to a different GPIO.
    if (WS2812_PIN_SECONDARY != WS2812_PIN_PRIMARY) {
        ws2812_program_init_local(ws2812_pio, ws2812_sm_secondary, offset, WS2812_PIN_SECONDARY, 800000, IS_RGBW);
        ws2812_secondary_enabled = true;
    }
}

static void led_set_rgb(uint8_t r, uint8_t g, uint8_t b) {
    uint32_t p0 = pack_color(r, g, b, WS2812_PRIMARY_IS_GRB != 0);
    uint32_t p1 = pack_color(r, g, b, WS2812_SECONDARY_IS_GRB != 0);
    put_pixel(p0, p1);
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
    rx_len = bufsize;
    packet_received = true;
}

// ----------------------------------------------------------------------------
// Token logic
// ----------------------------------------------------------------------------

static bool wait_for_user_presence(uint32_t timeout_ms) {
    absolute_time_t deadline = make_timeout_time_ms(timeout_ms);
    bool blink_on = false;
    absolute_time_t last_blink = get_absolute_time();

    while (absolute_time_diff_us(get_absolute_time(), deadline) > 0) {
        tud_task();

        if (get_bootsel_button_local()) {
            return true;
        }

        // Blue blink while waiting for approval.
        if (absolute_time_diff_us(last_blink, get_absolute_time()) >= 150000) {
            last_blink = get_absolute_time();
            blink_on = !blink_on;
            led_set_rgb(0, 0, blink_on ? 32 : 0);
        }
    }

    return false;
}

static void handle_sign(uint8_t tx[64], uint8_t version, uint8_t domain) {
    if (domain < DOMAIN_SUDO || domain > DOMAIN_LUKS) {
        tx[1] = STATUS_BAD_DOMAIN;
        return;
    }

    if (rx_len < 36) {
        tx[1] = STATUS_BAD_PAYLOAD;
        return;
    }

    if (!crypto_ready) {
        tx[1] = STATUS_CRYPTO_ERROR;
        return;
    }

    if (!wait_for_user_presence(APPROVAL_TIMEOUT_MS)) {
        tx[1] = STATUS_USER_PRESENCE_REQUIRED;

        // Yellow flash = denied / timeout.
        led_set_rgb(32, 32, 0);
        sleep_ms(120);
        led_set_rgb(0, 0, 0);
        return;
    }

    // Red flash while approving.
    led_set_rgb(32, 0, 0);
    sleep_ms(80);

    uint8_t domain_key[32];
    // Signed payload layout: version(1) || domain(1) || counter(4) || challenge(32).
    uint8_t msg[38];
    uint8_t mac[32];

    uint32_t next_counter = runtime_counter + 1;
    if (!flush_counter_checkpoint_if_needed(next_counter)) {
        tx[1] = STATUS_CRYPTO_ERROR;
        return;
    }
    runtime_counter = next_counter;
    uint32_t counter = runtime_counter;

    if (!derive_domain_key(device_root_key, domain, domain_key)) {
        tx[1] = STATUS_CRYPTO_ERROR;
        return;
    }

    msg[0] = version;
    msg[1] = domain;
    memcpy(&msg[2], &counter, sizeof(counter));
    memcpy(&msg[6], &rx_buf[4], 32);

    if (!hmac_sha256(domain_key, sizeof(domain_key), msg, sizeof(msg), mac)) {
        tx[1] = STATUS_CRYPTO_ERROR;
        return;
    }
    memcpy(&tx[4], mac, 32);
    memcpy(&tx[36], &counter, sizeof(counter));

    // White flash = success
    led_set_rgb(32, 32, 32);
    sleep_ms(120);
    led_set_rgb(0, 0, 0);
}

static void handle_provision(uint8_t tx[64]) {
    if (rx_len < 36) {
        tx[1] = STATUS_BAD_PAYLOAD;
        return;
    }

    if (!wait_for_user_presence(APPROVAL_TIMEOUT_MS)) {
        tx[1] = STATUS_USER_PRESENCE_REQUIRED;
        led_set_rgb(32, 32, 0);
        sleep_ms(120);
        led_set_rgb(0, 0, 0);
        return;
    }

    // Payload bytes [4..35] carry a replacement master secret.
    uint8_t new_master_secret[32];
    memcpy(new_master_secret, &rx_buf[4], sizeof(new_master_secret));

    // Always checkpoint live counter before rotating master secret.
    if (!persist_token_state(runtime_counter, new_master_secret, true)) {
        tx[1] = STATUS_CRYPTO_ERROR;
        return;
    }

    recompute_device_root_key();
    if (!crypto_ready) {
        tx[1] = STATUS_CRYPTO_ERROR;
        return;
    }

    tx[4] = 1; // Provisioning applied.
    led_set_rgb(32, 0, 32);
    sleep_ms(120);
    led_set_rgb(0, 0, 0);
}

static void handle_get_state(uint8_t tx[64]) {
    // tx[4..] is a compact diagnostics payload for host tooling.
    // [4]  protocol version
    // [5]  counter flush interval
    // [6]  flags: bit0 master secret provisioned, bit1 counter dirty in RAM
    // [8:12]  runtime counter (live)
    // [12:16] persisted counter checkpoint
    // [16:20] state generation
    // [20:28] device UID
    tx[4] = REQ_VERSION;
    tx[5] = (uint8_t)COUNTER_FLUSH_INTERVAL;
    tx[6] = 0;
    if (token_state.flags & TOKEN_FLAG_MASTER_SECRET_SET) {
        tx[6] |= 0x01;
    }
    if (runtime_counter != token_state.counter) {
        tx[6] |= 0x02;
    }

    memcpy(&tx[8], &runtime_counter, sizeof(runtime_counter));
    memcpy(&tx[12], &token_state.counter, sizeof(token_state.counter));
    memcpy(&tx[16], &token_state.generation, sizeof(token_state.generation));
    memcpy(&tx[20], device_uid.id, sizeof(device_uid.id));
}

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

    switch (command) {
        case CMD_SIGN:
            handle_sign(tx, version, domain);
            break;
        case CMD_PROVISION:
            handle_provision(tx);
            break;
        case CMD_GET_STATE:
            handle_get_state(tx);
            break;
        default:
            tx[1] = STATUS_BAD_COMMAND;
            break;
    }
}

// ----------------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------------
int main(void) {
    board_init();
    tusb_init();
    ws2812_init_led();

    pico_get_unique_board_id(&device_uid);
    load_token_state();
    recompute_device_root_key();

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
