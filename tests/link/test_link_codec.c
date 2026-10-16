/*
 * Host-side tests for src/link_codec.c against test-vectors/link/.
 *
 * tools/run-link-codec-tests.py turns the JSON vectors into a line-based script on stdin, so
 * this program needs no JSON parser. One command per line:
 *
 *   case <name>                 start a decode case: fresh receiver
 *   feed <report hex>           feed one report; a completed frame is recorded
 *   expect <frame hex>          the next frame the case must produce, in order
 *   end                         compare the frames produced with the ones expected
 *   encode <frame hex>          split this frame with the sender
 *   report <report hex>         the next report it must produce, in order
 *   endencode                   compare
 *   band <type> <band>          link_band(type) must equal band (link_band_t value)
 *   corr <body hex|-> <ok> <v>  link_parse_corr result
 *   status <16 numbers, fw_tag as hex>, then device <board> <vid> <pid> <poll_us> <name hex|->
 *   read_begin <corr> <status> <total> <crc> <schema>
 *   read_data <corr> <offset> <data hex>
 *   expectbody <hex>            the body the last status / read_* line must build
 *
 * Exit code 0 when every check passes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "link_codec.h"

#define MAX_LINE   8192
#define MAX_FRAMES 32
#define MAX_DEVS   16

static int failures, checks;

static int unhex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = strlen(hex);
    if (strcmp(hex, "-") == 0)
        return 0;
    if (n % 2 || n / 2 > cap)
        return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    return (int)(n / 2);
}

static void fail(const char *what, const char *name) {
    failures++;
    printf("FAIL %s: %s\n", name, what);
}

static void check(int ok, const char *what, const char *name) {
    checks++;
    if (!ok)
        fail(what, name);
}

static char *rest(char *line, const char *cmd) {
    char *p = line + strlen(cmd);
    while (*p == ' ')
        p++;
    return p;
}

int main(void) {
    static char line[MAX_LINE];
    static char name[256] = "";
    static link_rx_t rx;
    static link_tx_t tx;

    static uint8_t got[MAX_FRAMES][LINK_MAX_FRAME];
    static uint16_t got_len[MAX_FRAMES];
    static uint8_t want[MAX_FRAMES][LINK_MAX_FRAME];
    static int want_len[MAX_FRAMES];
    int n_got = 0, n_want = 0;

    static uint8_t built[LINK_MAX_FRAME];
    uint16_t built_len = 0;

    static link_device_t devs[MAX_DEVS];
    static link_status_t status;
    bool status_open = false;
    static uint8_t buf[LINK_MAX_FRAME];

    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0])
            continue;

        /* A status line is followed by device lines; build once they're done */
        if (status_open && strncmp(line, "device ", 7) != 0) {
            status.devices = devs;
            built_len = link_build_status(built, &status);
            status_open = false;
        }

        if (strncmp(line, "case ", 5) == 0) {
            snprintf(name, sizeof(name), "%s", rest(line, "case"));
            link_rx_reset(&rx);
            n_got = n_want = 0;
        } else if (strncmp(line, "feed ", 5) == 0) {
            int n = unhex(rest(line, "feed"), buf, sizeof(buf));
            uint16_t f = link_rx_feed(&rx, buf, (uint16_t)n);
            if (f && n_got < MAX_FRAMES) {
                memcpy(got[n_got], rx.buf, f);
                got_len[n_got++] = f;
            }
        } else if (strncmp(line, "expect ", 7) == 0) {
            want_len[n_want] = unhex(rest(line, "expect"), want[n_want], LINK_MAX_FRAME);
            n_want++;
        } else if (strcmp(line, "end") == 0) {
            int ok = n_got == n_want;
            for (int i = 0; ok && i < n_got; i++)
                ok = got_len[i] == want_len[i] && memcmp(got[i], want[i], got_len[i]) == 0;
            check(ok, "decoded frames differ", name);
        } else if (strncmp(line, "encode ", 7) == 0) {
            snprintf(name, sizeof(name), "encode %.40s", rest(line, "encode"));
            int n = unhex(rest(line, "encode"), buf, sizeof(buf));
            link_tx_reset(&tx);
            memcpy(link_tx_body(&tx), buf + LINK_HEADER_SIZE, n - LINK_HEADER_SIZE);
            link_tx_commit(&tx, buf[0], (uint16_t)(n - LINK_HEADER_SIZE));
            n_got = n_want = 0;
            while (n_got < MAX_FRAMES && link_tx_peek(&tx, got[n_got])) {
                got_len[n_got++] = LINK_REPORT_SIZE;
                link_tx_advance(&tx);
            }
            check(!link_tx_busy(&tx), "sender still busy", name);
        } else if (strncmp(line, "report ", 7) == 0) {
            want_len[n_want] = unhex(rest(line, "report"), want[n_want], LINK_MAX_FRAME);
            n_want++;
        } else if (strcmp(line, "endencode") == 0) {
            int ok = n_got == n_want;
            for (int i = 0; ok && i < n_got; i++)
                ok = want_len[i] == LINK_REPORT_SIZE && memcmp(got[i], want[i], LINK_REPORT_SIZE) == 0;
            check(ok, "reports differ", name);
        } else if (strncmp(line, "band ", 5) == 0) {
            unsigned type, band;
            sscanf(rest(line, "band"), "%x %u", &type, &band);
            snprintf(name, sizeof(name), "band 0x%02x", type);
            check(link_band((uint8_t)type) == (link_band_t)band, "wrong band", name);
        } else if (strncmp(line, "corr ", 5) == 0) {
            char hex[64];
            unsigned ok, value;
            uint32_t corr = 0;
            sscanf(rest(line, "corr"), "%63s %u %u", hex, &ok, &value);
            int n = unhex(hex, buf, sizeof(buf));
            snprintf(name, sizeof(name), "corr %s", hex);
            bool parsed = link_parse_corr(buf, (uint16_t)(n < 0 ? 0 : n), &corr);
            check(parsed == (bool)ok && (!parsed || corr == value), "corr parse", name);
        } else if (strncmp(line, "status ", 7) == 0) {
            unsigned v[15];
            char tag[64];
            memset(&status, 0, sizeof(status));
            sscanf(rest(line, "status"), "%u %u %63s %u %u %u %u %u %u %u %u %u %u %u %u %u",
                   &v[0], &v[1], tag, &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9],
                   &v[10], &v[11], &v[12], &v[13], &v[14]);
            status.corr = v[0];
            status.proto = (uint16_t)v[1];
            unhex(tag, (uint8_t *)status.fw_tag, LINK_FW_TAG_SIZE);
            status.schema = (uint16_t)v[2];
            status.board_type = (uint8_t)v[3];
            status.computer = (uint8_t)v[4];
            status.paired = (uint8_t)v[5];
            status.box_state = (uint8_t)v[6];
            status.max_profiles = (uint8_t)v[7];
            status.max_rules = (uint8_t)v[8];
            status.max_name = (uint8_t)v[9];
            status.max_blob = v[10];
            status.os_a = (uint8_t)v[11];
            status.os_b = (uint8_t)v[12];
            status.ss_hash_a = v[13];
            status.ss_hash_b = v[14];
            status.device_count = 0;
            snprintf(name, sizeof(name), "status corr %u", v[0]);
            status_open = true;
        } else if (strncmp(line, "device ", 7) == 0) {
            unsigned board, vid, pid, poll;
            char hex[128];
            link_device_t *d = &devs[status.device_count++];
            sscanf(rest(line, "device"), "%u %u %u %u %127s", &board, &vid, &pid, &poll, hex);
            d->board = (uint8_t)board;
            d->vid = (uint16_t)vid;
            d->pid = (uint16_t)pid;
            d->poll_us = (uint16_t)poll;
            int n = unhex(hex, (uint8_t *)d->name, LINK_DEVICE_NAME_MAX);
            d->name_len = (uint8_t)(n < 0 ? 0 : n);
        } else if (strncmp(line, "read_begin ", 11) == 0) {
            unsigned corr, st, total, crc, schema;
            sscanf(rest(line, "read_begin"), "%u %u %u %u %u", &corr, &st, &total, &crc, &schema);
            snprintf(name, sizeof(name), "read_begin corr %u", corr);
            built_len = link_build_read_begin(built, corr, (uint8_t)st, total, crc, (uint16_t)schema);
        } else if (strncmp(line, "read_data ", 10) == 0) {
            unsigned corr, offset;
            static char hex[MAX_LINE];
            sscanf(rest(line, "read_data"), "%u %u %8191s", &corr, &offset, hex);
            int n = unhex(hex, buf, sizeof(buf));
            snprintf(name, sizeof(name), "read_data offset %u", offset);
            built_len = link_build_read_data(built, corr, offset, buf, (uint16_t)n);
        } else if (strncmp(line, "expectbody ", 11) == 0) {
            int n = unhex(rest(line, "expectbody"), buf, sizeof(buf));
            check(n == built_len && memcmp(buf, built, built_len) == 0, "built body differs", name);
        } else {
            printf("FAIL unknown command: %.60s\n", line);
            failures++;
        }
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
