/*
 * This file is part of DeskHop (https://github.com/hrvach/deskhop).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * See the file LICENSE for the full license text.
 */
#pragma once

/* DeskHop Link frame codec: 64-byte reports with a frame-start flag, the 3-byte frame header,
   type bands, and the bodies of the open messages the box answers. Plain C with no Pico SDK
   dependencies, so tests/link builds it on the PC against test-vectors/link/.
   The wire format is protocol.md; tools/deskhop_link.py is the reference. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LINK_REPORT_SIZE    64
#define LINK_REPORT_PAYLOAD 63
#define LINK_FLAG_CONTINUE  0
#define LINK_FLAG_START     1
#define LINK_HEADER_SIZE    3
#define LINK_MAX_LEN        1024
#define LINK_MAX_FRAME      (LINK_HEADER_SIZE + LINK_MAX_LEN)
#define LINK_PROTO_VERSION  1

/* Message types (protocol.md, Message catalogue) */
enum link_type_e {
    LINK_STATUS_GET     = 0x01,
    LINK_STATUS         = 0x02,
    LINK_PAIR_REQUEST   = 0x03,
    LINK_PAIR_CHALLENGE = 0x04,
    LINK_PAIR_RESULT    = 0x05,
    LINK_HELLO          = 0x06,
    LINK_HELLO_REFUSED  = 0x07,
    LINK_READ_REQUEST   = 0x40,
    LINK_READ_BEGIN     = 0x41,
    LINK_READ_DATA      = 0x42,
};

typedef enum {
    LINK_BAND_DROP = 0,      // 0x00 padding, 0x50-0xFF reserved
    LINK_BAND_OPEN_PRIORITY, // 0x01-0x0F
    LINK_BAND_SIGNED_PRIORITY, // 0x10-0x2F
    LINK_BAND_SIGNED_BULK,   // 0x30-0x3F
    LINK_BAND_OPEN_BULK,     // 0x40-0x4F
} link_band_t;

link_band_t link_band(uint8_t type);

/* ---- Receiving: reports -> frames, with protocol.md's resync rules ---- */

typedef struct {
    uint8_t buf[LINK_MAX_FRAME];
    uint16_t have;
    uint16_t need;
    bool in_progress;
} link_rx_t;

void link_rx_reset(link_rx_t *rx);

/* Feed one report. Returns the frame length (header included) when a frame completes,
   the frame being in rx->buf; 0 otherwise. Anything that isn't a 64-byte report is dropped. */
uint16_t link_rx_feed(link_rx_t *rx, const uint8_t *report, uint16_t len);

/* ---- Sending: one frame at a time, split into reports ---- */

typedef struct {
    uint8_t buf[LINK_MAX_FRAME];
    uint16_t len;  // frame bytes
    uint16_t sent; // frame bytes already sent in earlier reports
} link_tx_t;

void link_tx_reset(link_tx_t *tx);
bool link_tx_busy(const link_tx_t *tx);

/* Body pointer for a new frame; finish with link_tx_commit(). Only while not busy. */
uint8_t *link_tx_body(link_tx_t *tx);
void link_tx_commit(link_tx_t *tx, uint8_t type, uint16_t body_len);

/* The next report of the frame in progress, without consuming it. False when idle. */
bool link_tx_peek(const link_tx_t *tx, uint8_t report[LINK_REPORT_SIZE]);

/* Call after the peeked report was handed to USB. */
void link_tx_advance(link_tx_t *tx);

/* ---- Message bodies ---- */

/* Requests that carry only a correlation ID (STATUS_GET, READ_REQUEST). False if malformed. */
bool link_parse_corr(const uint8_t *body, uint16_t len, uint32_t *corr);

#define LINK_FW_TAG_SIZE     16
#define LINK_DEVICE_NAME_MAX 32

typedef struct {
    uint8_t board;
    uint16_t vid;
    uint16_t pid;
    uint16_t poll_us;
    uint8_t name_len;
    char name[LINK_DEVICE_NAME_MAX];
} link_device_t;

typedef struct {
    uint32_t corr;
    uint16_t proto;
    char fw_tag[LINK_FW_TAG_SIZE]; // ASCII, zero-padded, not terminated when full
    uint16_t schema;
    uint8_t board_type;
    uint8_t computer;
    uint8_t paired;
    uint8_t box_state;
    uint8_t max_profiles;
    uint8_t max_rules;
    uint8_t max_name;
    uint32_t max_blob;
    uint8_t os_a;
    uint8_t os_b;
    uint32_t ss_hash_a;
    uint32_t ss_hash_b;
    uint8_t device_count;
    const link_device_t *devices;
} link_status_t;

#define LINK_STATUS_FIXED_SIZE 46
#define LINK_READ_CHUNK        512

/* Each returns the body length written to `out` (which must hold it). */
uint16_t link_build_status(uint8_t *out, const link_status_t *s);
uint16_t link_build_read_begin(uint8_t *out, uint32_t corr, uint8_t status, uint32_t total_len,
                               uint32_t crc32, uint16_t schema);
uint16_t link_build_read_data(uint8_t *out, uint32_t corr, uint32_t offset, const uint8_t *data,
                              uint16_t data_len);
