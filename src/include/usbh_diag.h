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

#include <stdbool.h>
#include <stdint.h>

/* Device-slot diagnostics, implemented in the vendored TinyUSB usbh.c. */
uint8_t tuh_diag_slots_used(void);     // Device slots (not hubs) marked connected, 0..CFG_TUH_DEVICE_MAX
bool tuh_diag_hub_connected(void);     // A hub occupies a hub slot
bool tuh_diag_any_mounted(void);       // Any device or hub finished enumeration
bool tuh_diag_enumerating(void);       // An enumeration is in progress
uint8_t tuh_diag_enum_abandoned(void); // Enumerations given up after retries (saturates at 255)
uint8_t tuh_diag_stale_cleared(void);  // Attaches that found and freed leaked slots (saturates)
uint8_t tuh_diag_addr_failed(void);    // SET_ADDRESS found no free slot (saturates)

/* One board's USB host health, 8 bytes so it fits a UART packet. */
typedef struct {
    uint8_t slots_used;     // With no hub this should never exceed 1
    uint8_t flags;          // HOST_STATUS_* bits
    uint8_t enum_abandoned;
    uint8_t stale_cleared;
    uint8_t addr_failed;
    uint8_t recoveries;     // Recovery reboots since power-on
    uint16_t uptime_min;
} __attribute__((packed)) host_status_t;

#define HOST_STATUS_HUB          (1 << 0)
#define HOST_STATUS_ENUMERATING  (1 << 1)
#define HOST_STATUS_PORT_CONN    (1 << 2) // Something is electrically attached to the socket
#define HOST_STATUS_MOUNTED      (1 << 3) // At least one device finished enumeration
#define HOST_STATUS_KEYBOARD     (1 << 4)
#define HOST_STATUS_MOUSE        (1 << 5)
#define HOST_STATUS_VALID        (1 << 7) // Block holds real data

/* Feature report REPORT_ID_HOST_STATUS: version, answering board, then A and B blocks each followed by age. */
#define HOST_STATUS_FORMAT       1
#define HOST_STATUS_REPORT_LEN   (2 + 2 * (sizeof(host_status_t) + 1))
#define HOST_STATUS_AGE_UNKNOWN  0xFF

/* Recovery: reboot this board when something is attached but nothing has mounted for this long. */
#define HOST_RECOVERY_TIMEOUT_S  8
#define HOST_RECOVERY_MAX_TRIES  3 // Consecutive recovery reboots without a successful mount
