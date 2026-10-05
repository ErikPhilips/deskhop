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
#include "host/hcd.h"
#include <math.h>

void task_scheduler(device_t *state, task_t *task) {
    uint64_t current_time = time_us_64();

    if (current_time < task->next_run)
        return;

    task->next_run = current_time + task->frequency;
    task->exec(state);
}

/* ================================================== *
 * ==============  Watchdog Functions  ============== *
 * ================================================== */

void kick_watchdog_task(device_t *state) {
    /* Read the timer AFTER duplicating the core1 timestamp,
       so it doesn't get updated in the meantime. */
    uint32_t core1_last_loop_pass = state->core1_last_loop_pass;
    uint32_t current_time         = time_us_32();

    /* If a reboot is requested, we'll stop updating watchdog */
    if (state->reboot_requested)
        return;

    /* If core1 stops updating the timestamp, we'll stop kicking the watchog and reboot */
    if ((uint32_t)(current_time - core1_last_loop_pass) < CORE1_HANG_TIMEOUT_US)
        watchdog_update();
}

/* ================================================== *
 * ===============  USB Device / Host  ============== *
 * ================================================== */

void usb_device_task(device_t *state) {
    tud_task();
}

void usb_host_task(device_t *state) {
    if (tuh_inited())
        tuh_task();
}

mouse_report_t *screensaver_pong(device_t *state) {
    static mouse_report_t report = {0};
    static int dx = 20, dy = 25;

    /* Check if we are bouncing off the walls and reverse direction in that case. */
    if (report.x + dx < MIN_SCREEN_COORD || report.x + dx > MAX_SCREEN_COORD)
        dx = -dx;

    if (report.y + dy < MIN_SCREEN_COORD || report.y + dy > MAX_SCREEN_COORD)
        dy = -dy;

    report.x += dx;
    report.y += dy;

    return &report;
}

mouse_report_t *screensaver_jitter(device_t *state) {
    static mouse_report_t report = {.mode = RELATIVE};
    static uint32_t heading_deg = 0;
    static float x = 0, y = 0;         /* Exact position along the circle */
    static int16_t sent_x = 0, sent_y = 0; /* Position already sent, in whole pixels */

    /* Move JITTER_STEP_PX along the current heading, then turn by JITTER_ANGLE_DEG; the moves trace a circle.
       Track the exact position and send the whole-pixel difference, so rounding never drifts the circle. */
    float heading = (float)heading_deg * (float)M_PI / 180.0f;
    x += JITTER_STEP_PX * cosf(heading);
    y += JITTER_STEP_PX * sinf(heading);
    heading_deg = (heading_deg + JITTER_ANGLE_DEG) % 360;

    int16_t next_x = (int16_t)lroundf(x);
    int16_t next_y = (int16_t)lroundf(y);
    report.x = next_x - sent_x;
    report.y = next_y - sent_y;
    sent_x = next_x;
    sent_y = next_y;

    return &report;
}

/* Have something fun and entertaining when idle. */
void screensaver_task(device_t *state) {
    const uint32_t delays[] = {
        0,        /* DISABLED, unused index 0 */
        5000,     /* PONG, move mouse every 5 ms for a high framerate */
        JITTER_STEP_US, /* JITTER, one move around the circle */
    };
    static uint32_t last_pointer_move = 0;
    screensaver_t *screensaver = &state->config.output[BOARD_ROLE].screensaver;
    uint64_t inactivity_period = time_us_64() - state->last_activity[BOARD_ROLE];

    /* If we're not enabled, nothing to do here. */
    if (screensaver->mode == DISABLED)
        return;

    /* System is still not idle for long enough to activate or screensaver mode is not supported */
    if (inactivity_period < screensaver->idle_time_us || screensaver->mode > MAX_SS_VAL)
        return;

    /* We exceeded the maximum permitted screensaver runtime */
    if (screensaver->max_time_us
        && inactivity_period > (screensaver->max_time_us + screensaver->idle_time_us))
        return;

    /* Jitter keeps out of the way: it pauses on any keyboard or mouse input, or while a key is held,
       and resumes once everything has been still for JITTER_IDLE_US */
    if (screensaver->mode == JITTER) {
        hid_keyboard_report_t held;
        combine_kbd_states(state, &held);

        if (inactivity_period < JITTER_IDLE_US || held.modifier || held.keycode[0])
            return;
    }

    /* If we're the selected output and we can only run on inactive output, nothing to do here. */
    if (screensaver->only_if_inactive && CURRENT_BOARD_IS_ACTIVE_OUTPUT)
        return;

    /* We're active! Now check if it's time to move the cursor yet. */
    if (time_us_32() - last_pointer_move < delays[screensaver->mode])
        return;

    /* Return, if we're not connected or the host is suspended */
    if(!tud_ready()) {
        return;
    }

    mouse_report_t *report;
    switch (screensaver->mode) {
        case PONG:
            report = screensaver_pong(state);
            break;

        case JITTER:
            report = screensaver_jitter(state);
            break;

        default:
            return;
    }

    /* Move mouse pointer */
    queue_mouse_report(report, state);

    /* Update timer of the last pointer move */
    last_pointer_move = time_us_32();
}

/* Periodically emit heartbeat packets */
void heartbeat_output_task(device_t *state) {
    /* If firmware upgrade is in progress, don't touch flash_cs */
    if (state->fw.upgrade_in_progress)
        return;

    if (state->config_mode_active) {
        /* Leave config mode if timeout expired and user didn't click exit */
        if (time_us_64() > state->config_mode_timer)
            reboot();

        /* Keep notifying the user we're still in config mode */
        blink_led(state);
    }

#ifdef DH_DEBUG
    /* Holding the button invokes bootsel firmware upgrade */
    if (is_bootsel_pressed())
        reset_usb_boot(1 << PICO_DEFAULT_LED_PIN, 0);
#endif

    uart_packet_t packet = {
        .type = HEARTBEAT_MSG,
        .data16 = {
            [0] = state->_running_fw.version,
            [2] = state->active_output,
        },
    };

    queue_try_add(&global_state.uart_tx_queue, &packet);
}


/* Recovery reboots survive in a watchdog scratch register; power-on clears it.
   Layout: magic in the top half, total recoveries in bits 8-15, consecutive ones in bits 0-7. */
#define RECOVERY_SCRATCH       0
#define RECOVERY_MAGIC         0xD1A60000
#define RECOVERY_MAGIC_MASK    0xFFFF0000

static uint32_t recovery_word(void) {
    uint32_t word = watchdog_hw->scratch[RECOVERY_SCRATCH];
    return ((word & RECOVERY_MAGIC_MASK) == RECOVERY_MAGIC) ? word : RECOVERY_MAGIC;
}

/* Once a second: refresh our USB host health, send it to the other board, and
   reboot ourselves if something is attached to the socket but nothing has mounted. */
void host_status_task(device_t *state) {
    uint32_t recovery = recovery_word();
    bool port_connected = hcd_port_connect_status(BOARD_TUH_RHPORT);
    bool any_mounted = tuh_diag_any_mounted();

    host_status_t *mine = &state->host_status[BOARD_ROLE];
    *mine = (host_status_t){
        .slots_used     = tuh_diag_slots_used(),
        .flags          = HOST_STATUS_VALID
                        | (tuh_diag_hub_connected() ? HOST_STATUS_HUB : 0)
                        | (tuh_diag_enumerating() ? HOST_STATUS_ENUMERATING : 0)
                        | (port_connected ? HOST_STATUS_PORT_CONN : 0)
                        | (any_mounted ? HOST_STATUS_MOUNTED : 0)
                        | (state->keyboard_connected ? HOST_STATUS_KEYBOARD : 0)
                        | (state->mouse_connected ? HOST_STATUS_MOUSE : 0),
        .enum_abandoned = tuh_diag_enum_abandoned(),
        .stale_cleared  = tuh_diag_stale_cleared(),
        .addr_failed    = tuh_diag_addr_failed(),
        .recoveries     = (recovery >> 8) & 0xFF,
        .uptime_min     = (uint16_t)(time_us_64() / 60000000ULL),
    };
    state->host_status_time[BOARD_ROLE] = time_us_64();

    uart_packet_t packet = {.type = HOST_STATUS_MSG};
    memcpy(packet.data, mine, sizeof(host_status_t));
    queue_try_add(&global_state.uart_tx_queue, &packet);

    /* A device mounted: the host works, so the consecutive-recovery budget is restored. */
    if (any_mounted && (recovery & 0xFF)) {
        recovery &= ~0xFFu;
        watchdog_hw->scratch[RECOVERY_SCRATCH] = recovery;
    }

    if (!port_connected || any_mounted) {
        state->host_unmounted_secs = 0;
        return;
    }

    /* Leave config mode and firmware transfers alone; they reboot on their own terms. */
    if (state->config_mode_active || state->fw.upgrade_in_progress)
        return;

    if (++state->host_unmounted_secs < HOST_RECOVERY_TIMEOUT_S)
        return;

    /* Give up after a few tries, a device that never enumerates shouldn't cause a reboot loop. */
    if ((recovery & 0xFF) >= HOST_RECOVERY_MAX_TRIES)
        return;

    uint32_t total = (recovery >> 8) & 0xFF;
    if (total < 0xFF)
        total++;

    watchdog_hw->scratch[RECOVERY_SCRATCH] = RECOVERY_MAGIC | (total << 8) | ((recovery & 0xFF) + 1);
    reboot();
}

/* Process other outgoing hid report messages. */
void process_hid_queue_task(device_t *state) {
    hid_generic_pkt_t packet;

    if (!queue_try_peek(&state->hid_queue_out, &packet))
        return;

    if (!tud_hid_n_ready(packet.instance))
        return;

    /* ... try sending it to the host, if it's successful */
    bool succeeded = tud_hid_n_report(packet.instance, packet.report_id, packet.data, packet.len);

    /* ... then we can remove it from the queue. Race conditions shouldn't happen [tm] */
    if (succeeded)
        queue_try_remove(&state->hid_queue_out, &packet);
}

/* Task that handles copying firmware from the other device to ours */
void firmware_upgrade_task(device_t *state) {
    if (!state->fw.upgrade_in_progress || !state->fw.byte_done)
        return;

    if (queue_is_full(&state->uart_tx_queue))
        return;

    /* If we're on the last element of the current page, page is done - write it.
       Address zero is not the end of a page: nothing has arrived yet */
    if (TU_U32_BYTE0(state->fw.address) == 0x00 && state->fw.address != 0) {

        uint32_t page_start_addr = (state->fw.address - 1) & 0xFFFFFF00;
        write_flash_page((uint32_t)ADDR_FW_RUNNING + page_start_addr - XIP_BASE, state->page_buffer);
    }

    /* End condition, when reached the process is completed. */
    if (state->fw.address >= STAGING_IMAGE_SIZE) {
        state->fw.upgrade_in_progress = 0;
        state->fw.checksum = ~state->fw.checksum;

        /* Checksum mismatch, we wipe the stage 2 bootloader and rely on ROM recovery */
        if(calculate_firmware_crc32() != state->fw.checksum) {
            flash_range_erase((uint32_t)ADDR_FW_RUNNING - XIP_BASE, FLASH_SECTOR_SIZE);
            reset_usb_boot(1 << PICO_DEFAULT_LED_PIN, 0);
        }

        else {
            state->_running_fw = _firmware_metadata;
            global_state.reboot_requested = true;
        }

        return;
    }

    request_byte(state, state->fw.address);
}

void packet_receiver_task(device_t *state) {
    uint32_t current_pointer
        = (uint32_t)DMA_RX_BUFFER_SIZE - dma_channel_hw_addr(state->dma_rx_channel)->transfer_count;
    uint32_t delta = get_ptr_delta(current_pointer, state);

    /* If we don't have enough characters for a packet, skip loop and return immediately */
    while (delta >= RAW_PACKET_LENGTH) {
        if (is_start_of_packet(state)) {
            fetch_packet(state);
            process_packet(&state->in_packet, state);
            return;
        }

        /* No packet found, advance to next position and decrement delta */
        state->dma_ptr = NEXT_RING_IDX(state->dma_ptr);
        delta--;
    }
}
