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
#pragma once

#include <stdint.h>

enum packet_type_e {
    KEYBOARD_REPORT_MSG  = 1,
    MOUSE_REPORT_MSG     = 2,
    OUTPUT_SELECT_MSG    = 3,
    FIRMWARE_UPGRADE_MSG = 4,
    MOUSE_ZOOM_MSG       = 5,
    KBD_SET_REPORT_MSG   = 6,
    SWITCH_LOCK_MSG      = 7,
    SYNC_BORDERS_MSG     = 8,
    FLASH_LED_MSG        = 9,
    WIPE_CONFIG_MSG      = 10,
    SCREENSAVER_MSG      = 11,
    HEARTBEAT_MSG        = 12,
    GAMING_MODE_MSG      = 13,
    CONSUMER_CONTROL_MSG = 14,
    SYSTEM_CONTROL_MSG   = 15,
    SAVE_CONFIG_MSG      = 18,
    REBOOT_MSG           = 19,
    /* 20-23 were the web config page's GET/SET/READ_ALL/PROXY messages, removed with the
       config channel. Keep the numbers unused. */
    REQUEST_BYTE_MSG     = 24,
    RESPONSE_BYTE_MSG    = 25,
    HOST_STATUS_MSG      = 26,
};
