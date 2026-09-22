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

/* ==================================================== *
 * ========== Update pico and keyboard LEDs  ========== *
 * ==================================================== */

void set_keyboard_leds(uint8_t requested_led_state, device_t *state) {
    static uint8_t new_led_value;

    new_led_value = requested_led_state;
    if (state->keyboard_connected) {
        if(tuh_hid_set_report(state->kbd_dev_addr,
                              state->kbd_instance,
                              0,
                              HID_REPORT_TYPE_OUTPUT,
                              &new_led_value,
                              sizeof(uint8_t)))

            state->keyboard_leds_actual[BOARD_ROLE] = requested_led_state;
    }
}

void restore_leds(device_t *state) {
    /* Light up on-board LED if current board is active output */
    state->onboard_led_state = (state->active_output == BOARD_ROLE);
    gpio_put(GPIO_LED_PIN, state->onboard_led_state);

    /* Light up appropriate keyboard leds (if it's connected locally) */
    if (state->keyboard_connected) {
        uint8_t leds = state->keyboard_leds_desired[state->active_output];
        set_keyboard_leds(leds, state);
    }
}

uint8_t toggle_led(void) {
    uint8_t new_led_state = gpio_get(GPIO_LED_PIN) ^ 1;
    gpio_put(GPIO_LED_PIN, new_led_state);

    return new_led_state;
}

void blink_led(device_t *state) {
    /* Since LEDs might be ON previously, we go OFF, ON, OFF, ON, OFF */
    state->blinks_left     = 5;
    state->last_led_change = time_us_32();
}

/* Screensaver mode of whichever output is active: ours from config, theirs from the last status message */
static uint8_t active_output_screensaver_mode(device_t *state) {
    if (CURRENT_BOARD_IS_ACTIVE_OUTPUT)
        return state->config.output[BOARD_ROLE].screensaver.mode;

    return state->remote_screensaver_mode;
}

void led_sync_task(device_t *state) {
    static uint32_t last_caps_toggle = 0;
    static bool caps_blink_on = false;

    /* Acknowledge blinks own the LEDs while they run */
    if (state->blinks_left > 0)
        return;

    /* Check if keyboard LEDs need to be updated */
    if (state->keyboard_connected) {
        uint8_t desired_leds = state->keyboard_leds_desired[state->active_output];

        /* While jitter runs on the active output, blink Caps Lock as a visible "it's on" indicator */
        if (active_output_screensaver_mode(state) == JITTER) {
            if (time_us_32() - last_caps_toggle >= CAPS_BLINK_INTERVAL_US) {
                caps_blink_on = !caps_blink_on;
                last_caps_toggle = time_us_32();
            }
            desired_leds = caps_blink_on ? (desired_leds | KEYBOARD_LED_CAPSLOCK)
                                         : (desired_leds & ~KEYBOARD_LED_CAPSLOCK);
        }

#if PEN_ABSOLUTE_TEST
        /* Test-build indicator: Caps Lock LED on while absolute (pen) mode is active, off in gaming mode */
        desired_leds = state->gaming_mode ? (desired_leds & ~KEYBOARD_LED_CAPSLOCK)
                                          : (desired_leds | KEYBOARD_LED_CAPSLOCK);
#endif

        if (state->keyboard_leds_actual[BOARD_ROLE] != desired_leds)
            set_keyboard_leds(desired_leds, state);
    }
}

void led_blinking_task(device_t *state) {
    const int blink_interval_us = 80000; /* 80 ms off, 80 ms on */
    static uint8_t leds;

    /* If there is no more blinking to be done, exit immediately */
    if (state->blinks_left == 0)
        return;

    /* We have some blinks left to do, check if they are due, exit if not */
    if ((time_us_32()) - state->last_led_change < blink_interval_us)
        return;

    /* Toggle the LED state */
    uint8_t new_led_state = toggle_led();

    /* Also keyboard leds (if it's connected locally) since on-board leds are not visible */
    leds = new_led_state * 0x07; /* Numlock, capslock, scrollock */

    if (state->keyboard_connected)
        set_keyboard_leds(leds, state);

    /* Decrement the counter and update the last-changed timestamp */
    state->blinks_left--;
    state->last_led_change = time_us_32();

    /* Restore LEDs in the last pass */
    if (state->blinks_left == 0)
        restore_leds(state);
}
