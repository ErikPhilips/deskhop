/*
 * This file is part of DeskHop (https://github.com/hrvach/deskhop).
 * Copyright (c) 2025 Hrvoje Cavrak
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * See the file LICENSE for the full license text.
 */
#include "main.h"

void _queue_packet(uint8_t *payload, device_t *state, uint8_t type, uint8_t len, uint8_t id, uint8_t inst) {
    hid_generic_pkt_t generic_packet = {
        .instance = inst,
        .report_id = id,
        .type = type,
        .len = len,
    };

    memcpy(generic_packet.data, payload, len);
    queue_try_add(&state->hid_queue_out, &generic_packet);
}

void queue_cc_packet(uint8_t *payload, device_t *state) {
    _queue_packet(payload, state, 1, CONSUMER_CONTROL_LENGTH, REPORT_ID_CONSUMER, ITF_NUM_HID);
}

void queue_system_packet(uint8_t *payload, device_t *state) {
    _queue_packet(payload, state, 2, SYSTEM_CONTROL_LENGTH, REPORT_ID_SYSTEM, ITF_NUM_HID);
}
