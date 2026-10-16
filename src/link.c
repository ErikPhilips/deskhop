/*
 * This file is part of DeskHop (https://github.com/hrvach/deskhop).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * See the file LICENSE for the full license text.
 */

#include <stdio.h>

#include "main.h"

#ifndef GIT_SHORT_SHA
#define GIT_SHORT_SHA ""
#endif

#define STATUS_PENDING_MAX 4

static link_rx_t link_rx;
static link_tx_t link_tx;

/* STATUS_GET correlation IDs waiting for their STATUS (priority queue) */
static uint32_t status_pending[STATUS_PENDING_MAX];
static uint8_t status_pending_count;

/* Get configuration in progress (bulk queue). The blob is a snapshot of this board's live
   config_t, taken when the request arrives. Both boards hold both outputs' settings (the old
   config page always wrote both), so one board's copy is the whole desk. */
static struct {
    bool active;
    bool begun;
    uint32_t corr;
    uint32_t offset;
    uint32_t crc;
    uint8_t blob[sizeof(config_t)];
} link_read;

void link_reset(void) {
    link_rx_reset(&link_rx);
    link_tx_reset(&link_tx);
    status_pending_count = 0;
    link_read.active = false;
}

static void start_read(device_t *state, uint32_t corr) {
    /* A new request replaces one still in progress; the app retries a read it didn't finish */
    memcpy(link_read.blob, &state->config, sizeof(config_t));
    link_read.crc    = calc_crc32(link_read.blob, sizeof(config_t));
    link_read.corr   = corr;
    link_read.offset = 0;
    link_read.begun  = false;
    link_read.active = true;
}

/* Every frame the box can't answer yet is dropped silently: signed bands (no sessions in this
   build), pairing and HELLO, box-to-host types arriving from the host, reserved types. */
static void handle_frame(device_t *state, const uint8_t *frame, uint16_t len) {
    const uint8_t *body = frame + LINK_HEADER_SIZE;
    uint16_t body_len = len - LINK_HEADER_SIZE;
    uint32_t corr;

    switch (frame[0]) {
        case LINK_STATUS_GET:
            if (!link_parse_corr(body, body_len, &corr))
                return;
            if (status_pending_count < STATUS_PENDING_MAX)
                status_pending[status_pending_count++] = corr;
            return;

        case LINK_READ_REQUEST:
            if (link_parse_corr(body, body_len, &corr))
                start_read(state, corr);
            return;

        default:
            return;
    }
}

void link_receive_report(device_t *state, const uint8_t *report, uint16_t len) {
    uint16_t frame_len = link_rx_feed(&link_rx, report, len);

    if (frame_len)
        handle_frame(state, link_rx.buf, frame_len);
}

static void build_status(device_t *state, uint32_t corr) {
    static link_device_t devices[CFG_TUH_DEVICE_MAX];
    uint8_t count = 0;
    char tag[LINK_FW_TAG_SIZE + 1];

    /* Only this board's devices: the inter-board link doesn't carry the sibling's yet. */
    for (uint8_t addr = 1; addr <= CFG_TUH_DEVICE_MAX; addr++) {
        uint16_t vid, pid;

        if (tuh_mounted(addr) && tuh_vid_pid_get(addr, &vid, &pid))
            devices[count++] = (link_device_t){.board = BOARD_ROLE, .vid = vid, .pid = pid};
    }

    link_status_t status = {
        .corr         = corr,
        .proto        = LINK_PROTO_VERSION,
        .schema       = CURRENT_CONFIG_VERSION,
        .board_type   = LINK_BOARD_TYPE_RP2040,
        .computer     = BOARD_ROLE,
        .device_count = count,
        .devices      = devices,
        /* Not backed by anything yet, zero: paired, box_state, limits, os_a/os_b, ss_hash_a/b */
    };

    int tag_len = snprintf(tag, sizeof(tag), "%d.%02d%s%s", VERSION_MAJOR, VERSION_MINOR,
                           GIT_SHORT_SHA[0] ? "-" : "", GIT_SHORT_SHA);
    if (tag_len > 0)
        memcpy(status.fw_tag, tag, tag_len < LINK_FW_TAG_SIZE ? tag_len : LINK_FW_TAG_SIZE);

    link_tx_commit(&link_tx, LINK_STATUS, link_build_status(link_tx_body(&link_tx), &status));
}

static void build_next_read_frame(void) {
    uint8_t *body = link_tx_body(&link_tx);

    if (!link_read.begun) {
        link_read.begun = true;
        link_tx_commit(&link_tx, LINK_READ_BEGIN,
                       link_build_read_begin(body, link_read.corr, 0, sizeof(config_t), link_read.crc,
                                             CURRENT_CONFIG_VERSION));
        return;
    }

    uint32_t left = sizeof(config_t) - link_read.offset;
    uint16_t chunk = left > LINK_READ_CHUNK ? LINK_READ_CHUNK : left;

    link_tx_commit(&link_tx, LINK_READ_DATA,
                   link_build_read_data(body, link_read.corr, link_read.offset,
                                        &link_read.blob[link_read.offset], chunk));
    link_read.offset += chunk;

    if (link_read.offset >= sizeof(config_t))
        link_read.active = false;
}

/* Priority before bulk, between frames: a frame's reports always go out back to back. */
static void build_next_frame(device_t *state) {
    if (status_pending_count) {
        uint32_t corr = status_pending[0];

        status_pending_count--;
        memmove(&status_pending[0], &status_pending[1], status_pending_count * sizeof(uint32_t));
        build_status(state, corr);
        return;
    }

    if (link_read.active)
        build_next_read_frame();
}

/* Hand the next report to USB whenever the link's IN endpoint is free */
void link_task(device_t *state) {
    uint8_t report[LINK_REPORT_SIZE];

    if (state->config_mode_active || !tud_hid_n_ready(ITF_NUM_HID_LINK))
        return;

    if (!link_tx_busy(&link_tx))
        build_next_frame(state);

    if (!link_tx_peek(&link_tx, report))
        return;

    if (tud_hid_n_report(ITF_NUM_HID_LINK, REPORT_ID_NONE, report, LINK_REPORT_SIZE))
        link_tx_advance(&link_tx);
}
