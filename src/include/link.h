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

/* DeskHop Link: the helper app <-> box channel on its own vendor HID interface (protocol.md).
   This build answers only the open, read-only messages: STATUS_GET -> STATUS and
   READ_REQUEST -> READ_BEGIN + READ_DATA. Every other type is dropped silently.
   Everything here runs on core0, alongside the TinyUSB device stack. */

#include "link_codec.h"
#include "structs.h"

#define LINK_BOARD_TYPE_RP2040 1

void link_reset(void);
void link_receive_report(device_t *state, const uint8_t *report, uint16_t len);
void link_task(device_t *state);
