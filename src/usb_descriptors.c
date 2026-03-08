#include "tusb.h"
#include "pico/unique_id.h"

// -----------------------------------------------------------------------------
// Device descriptor
// -----------------------------------------------------------------------------

tusb_desc_device_t const desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor           = 0xCafe,
    .idProduct          = 0x4011,
    .bcdDevice          = 0x0100,

    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,

    .bNumConfigurations = 0x01
};

uint8_t const * tud_descriptor_device_cb(void) {
    return (uint8_t const *) &desc_device;
}

// -----------------------------------------------------------------------------
// HID report descriptor - vendor defined 64 in / 64 out
// -----------------------------------------------------------------------------

uint8_t const hid_report_desc[] = {
    0x06, 0x00, 0xFF,        // Usage Page (Vendor Defined)
    0x09, 0x01,              // Usage
    0xA1, 0x01,              // Collection (Application)

    0x09, 0x02,              //   Usage
    0x15, 0x00,              //   Logical Min (0)
    0x26, 0xFF, 0x00,        //   Logical Max (255)
    0x75, 0x08,              //   Report Size (8)
    0x95, 0x40,              //   Report Count (64)
    0x81, 0x02,              //   Input (Data,Var,Abs)

    0x09, 0x03,              //   Usage
    0x15, 0x00,              //   Logical Min (0)
    0x26, 0xFF, 0x00,        //   Logical Max (255)
    0x75, 0x08,              //   Report Size (8)
    0x95, 0x40,              //   Report Count (64)
    0x91, 0x02,              //   Output (Data,Var,Abs)

    0xC0                     // End Collection
};

uint8_t const * tud_hid_descriptor_report_cb(uint8_t instance) {
    (void) instance;
    return hid_report_desc;
}

// -----------------------------------------------------------------------------
// Configuration descriptor
// -----------------------------------------------------------------------------

enum {
    ITF_NUM_HID,
    ITF_NUM_TOTAL
};

#define CONFIG_TOTAL_LEN    (TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN)
#define EPNUM_HID           0x81
#define EPNUM_HID_OUT       0x01

uint8_t const desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 100),
    TUD_HID_DESCRIPTOR(ITF_NUM_HID, 0, HID_ITF_PROTOCOL_NONE,
                       sizeof(hid_report_desc), EPNUM_HID, 16, 5),
};

uint8_t const * tud_descriptor_configuration_cb(uint8_t index) {
    (void) index;
    return desc_configuration;
}

// -----------------------------------------------------------------------------
// String descriptors
// -----------------------------------------------------------------------------

char const *string_desc_arr[] = {
    (const char[]) { 0x09, 0x04 },
    "mveplus",
    "RP2350 HID Token",
    NULL,
};

static uint16_t _desc_str[32];

uint16_t const * tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void) langid;
    uint8_t chr_count;
    char serial_ascii[PICO_UNIQUE_BOARD_ID_SIZE_BYTES * 2 + 1];

    if (index == 0) {
        _desc_str[1] = 0x0409;
        chr_count = 1;
    } else if (index == 3) {
        // Export hardware UID as serial so host tooling can identify the token.
        pico_get_unique_board_id_string(serial_ascii, sizeof(serial_ascii));
        chr_count = 0;
        while (serial_ascii[chr_count] && chr_count < 31) {
            _desc_str[1 + chr_count] = serial_ascii[chr_count];
            chr_count++;
        }
    } else {
        if (!(index < sizeof(string_desc_arr) / sizeof(string_desc_arr[0]))) {
            return NULL;
        }

        const char *str = string_desc_arr[index];
        chr_count = 0;
        while (str[chr_count] && chr_count < 31) {
            _desc_str[1 + chr_count] = str[chr_count];
            chr_count++;
        }
    }

    _desc_str[0] = (uint16_t) ((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));
    return _desc_str;
}
