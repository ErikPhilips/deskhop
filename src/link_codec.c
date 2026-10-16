/*
 * This file is part of DeskHop (https://github.com/hrvach/deskhop).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * See the file LICENSE for the full license text.
 */

#include <string.h>

#include "link_codec.h"

link_band_t link_band(uint8_t type) {
    if (type == 0x00)
        return LINK_BAND_DROP;
    if (type <= 0x0F)
        return LINK_BAND_OPEN_PRIORITY;
    if (type <= 0x2F)
        return LINK_BAND_SIGNED_PRIORITY;
    if (type <= 0x3F)
        return LINK_BAND_SIGNED_BULK;
    if (type <= 0x4F)
        return LINK_BAND_OPEN_BULK;
    return LINK_BAND_DROP;
}

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint8_t *put_u8(uint8_t *p, uint8_t v) {
    *p++ = v;
    return p;
}

static uint8_t *put_u16(uint8_t *p, uint16_t v) {
    *p++ = v & 0xFF;
    *p++ = v >> 8;
    return p;
}

static uint8_t *put_u32(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++)
        *p++ = (v >> (8 * i)) & 0xFF;
    return p;
}

static uint8_t *put_bytes(uint8_t *p, const void *src, size_t n) {
    memcpy(p, src, n);
    return p + n;
}

/* ================================================== *
 * Receiving
 * ================================================== */

void link_rx_reset(link_rx_t *rx) {
    rx->have = 0;
    rx->need = 0;
    rx->in_progress = false;
}

/* Take this report's share of the frame in progress. Returns the frame length when complete. */
static uint16_t rx_take(link_rx_t *rx, const uint8_t *payload) {
    uint16_t n = rx->need - rx->have;
    if (n > LINK_REPORT_PAYLOAD)
        n = LINK_REPORT_PAYLOAD;

    memcpy(rx->buf + rx->have, payload, n);
    rx->have += n;

    if (rx->have < rx->need)
        return 0;

    rx->in_progress = false;

    /* The rest of the frame's last report must be padding, or the frame is dropped */
    for (uint16_t i = n; i < LINK_REPORT_PAYLOAD; i++)
        if (payload[i])
            return 0;

    return rx->need;
}

uint16_t link_rx_feed(link_rx_t *rx, const uint8_t *report, uint16_t len) {
    if (len != LINK_REPORT_SIZE)
        return 0;

    uint8_t flag = report[0];
    const uint8_t *payload = &report[1];

    if (flag == LINK_FLAG_CONTINUE) {
        /* Tail of a frame whose head was lost: drop the report */
        if (!rx->in_progress)
            return 0;
        return rx_take(rx, payload);
    }

    /* Flag 1 while a frame is in progress means that frame lost a report: drop it.
       Any flag other than 0 or 1 drops the report and the frame in progress. */
    rx->in_progress = false;
    if (flag != LINK_FLAG_START)
        return 0;

    uint8_t type = payload[0];
    uint16_t length = get_u16(&payload[1]);

    if (type == 0x00 || length > LINK_MAX_LEN)
        return 0;

    rx->have = 0;
    rx->need = LINK_HEADER_SIZE + length;
    rx->in_progress = true;
    return rx_take(rx, payload);
}

/* ================================================== *
 * Sending
 * ================================================== */

void link_tx_reset(link_tx_t *tx) {
    tx->len = 0;
    tx->sent = 0;
}

bool link_tx_busy(const link_tx_t *tx) {
    return tx->sent < tx->len;
}

uint8_t *link_tx_body(link_tx_t *tx) {
    return tx->buf + LINK_HEADER_SIZE;
}

void link_tx_commit(link_tx_t *tx, uint8_t type, uint16_t body_len) {
    tx->buf[0] = type;
    put_u16(&tx->buf[1], body_len);
    tx->len = LINK_HEADER_SIZE + body_len;
    tx->sent = 0;
}

bool link_tx_peek(const link_tx_t *tx, uint8_t report[LINK_REPORT_SIZE]) {
    if (!link_tx_busy(tx))
        return false;

    uint16_t n = tx->len - tx->sent;
    if (n > LINK_REPORT_PAYLOAD)
        n = LINK_REPORT_PAYLOAD;

    memset(report, 0, LINK_REPORT_SIZE);
    report[0] = tx->sent == 0 ? LINK_FLAG_START : LINK_FLAG_CONTINUE;
    memcpy(&report[1], tx->buf + tx->sent, n);
    return true;
}

void link_tx_advance(link_tx_t *tx) {
    uint16_t n = tx->len - tx->sent;
    tx->sent += n > LINK_REPORT_PAYLOAD ? LINK_REPORT_PAYLOAD : n;
}

/* ================================================== *
 * Message bodies
 * ================================================== */

bool link_parse_corr(const uint8_t *body, uint16_t len, uint32_t *corr) {
    if (len != 4)
        return false;

    *corr = (uint32_t)body[0] | ((uint32_t)body[1] << 8) | ((uint32_t)body[2] << 16) |
            ((uint32_t)body[3] << 24);
    return true;
}

uint16_t link_build_status(uint8_t *out, const link_status_t *s) {
    uint8_t *p = out;

    p = put_u32(p, s->corr);
    p = put_u16(p, s->proto);
    p = put_bytes(p, s->fw_tag, LINK_FW_TAG_SIZE);
    p = put_u16(p, s->schema);
    p = put_u8(p, s->board_type);
    p = put_u8(p, s->computer);
    p = put_u8(p, s->paired);
    p = put_u8(p, s->box_state);
    p = put_u8(p, s->max_profiles);
    p = put_u8(p, s->max_rules);
    p = put_u8(p, s->max_name);
    p = put_u32(p, s->max_blob);
    p = put_u8(p, s->os_a);
    p = put_u8(p, s->os_b);
    p = put_u32(p, s->ss_hash_a);
    p = put_u32(p, s->ss_hash_b);
    p = put_u8(p, s->device_count);

    for (int i = 0; i < s->device_count; i++) {
        const link_device_t *d = &s->devices[i];
        uint8_t name_len = d->name_len > LINK_DEVICE_NAME_MAX ? LINK_DEVICE_NAME_MAX : d->name_len;

        p = put_u8(p, d->board);
        p = put_u16(p, d->vid);
        p = put_u16(p, d->pid);
        p = put_u16(p, d->poll_us);
        p = put_u8(p, name_len);
        p = put_bytes(p, d->name, name_len);
    }

    return (uint16_t)(p - out);
}

uint16_t link_build_read_begin(uint8_t *out, uint32_t corr, uint8_t status, uint32_t total_len,
                               uint32_t crc32, uint16_t schema) {
    uint8_t *p = out;

    p = put_u32(p, corr);
    p = put_u8(p, status);
    p = put_u32(p, total_len);
    p = put_u32(p, crc32);
    p = put_u16(p, schema);
    return (uint16_t)(p - out);
}

uint16_t link_build_read_data(uint8_t *out, uint32_t corr, uint32_t offset, const uint8_t *data,
                              uint16_t data_len) {
    uint8_t *p = out;

    if (data_len > LINK_READ_CHUNK)
        data_len = LINK_READ_CHUNK;

    p = put_u32(p, corr);
    p = put_u32(p, offset);
    p = put_bytes(p, data, data_len);
    return (uint16_t)(p - out);
}
