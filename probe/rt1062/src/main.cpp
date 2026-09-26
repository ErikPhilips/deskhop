// RT1062 first-light probe.
// Mouse in the carrier's USB-A (USB2, high-speed host) -> Teensy -> USB-C (USB1, high-speed device) -> PC.
// Each mouse report is queued in the USB callback and sent to the PC one for one, so report timing
// is preserved. Only if the queue fills (PC slower than the mouse) are reports merged, and counted.
// Every second, prints rates and diagnostics over USB serial.

#include <Arduino.h>
#include <USBHost_t36.h>

struct MouseReport { int16_t x, y; int8_t w, h; uint8_t buttons; };

static const uint32_t QLEN = 64;                 /* power of two */
static volatile MouseReport q[QLEN];
static volatile uint32_t q_head = 0, q_tail = 0; /* head written by ISR, tail by loop */
static volatile uint32_t in_reports = 0, in_empty = 0, in_merged = 0;

class QueueingMouse : public MouseController {
public:
    QueueingMouse(USBHost &host) : MouseController(host) {}
    int speed() { return mydevice ? mydevice->speed : -1; }

protected:
    uint8_t last_buttons = 0;

    void hid_input_end() override {
        MouseController::hid_input_end();          /* fills mouseX etc. from this one report */
        int x = getMouseX(), y = getMouseY(), w = getWheel(), h = getWheelH();
        uint8_t b = getButtons();
        mouseDataClear();
        in_reports++;

        if (x == 0 && y == 0 && w == 0 && h == 0 && b == last_buttons) {
            in_empty++;                            /* nothing to tell the PC */
            return;
        }
        last_buttons = b;

        uint32_t head = q_head;
        if (head - q_tail >= QLEN) {
            /* Queue full: merge into the newest entry rather than drop movement */
            volatile MouseReport &r = q[(head - 1) & (QLEN - 1)];
            r.x += x; r.y += y; r.w += w; r.h += h; r.buttons = b;
            in_merged++;
            return;
        }
        volatile MouseReport &r = q[head & (QLEN - 1)];
        r.x = x; r.y = y; r.w = w; r.h = h; r.buttons = b;
        q_head = head + 1;
    }
};

USBHost myusb;
USBHub hub1(myusb);
USBHIDParser hid1(myusb);
USBHIDParser hid2(myusb);
USBHIDParser hid3(myusb);
USBHIDParser hid4(myusb);
QueueingMouse mouse1(myusb);

static uint32_t out_count = 0, window_start = 0, peak_in = 0, last_in = 0, last_empty = 0, last_merged = 0;
static uint32_t q_max = 0;
static uint8_t sent_buttons = 0;

static inline int8_t clamp8(int v) { return v > 127 ? 127 : (v < -127 ? -127 : v); }

void setup() {
    Serial.begin(115200);
    myusb.begin();
    window_start = millis();
}

void loop() {
    myusb.Task();

    uint32_t depth = q_head - q_tail;
    if (depth > q_max) q_max = depth;

    if (depth) {
        MouseReport r;
        __disable_irq();
        volatile MouseReport &src = q[q_tail & (QLEN - 1)];
        r.x = src.x; r.y = src.y; r.w = src.w; r.h = src.h; r.buttons = src.buttons;
        q_tail = q_tail + 1;
        __enable_irq();

        if (r.buttons != sent_buttons) {
            /* MouseController: bit0 left, bit1 right, bit2 middle, bit3 back, bit4 forward.
               Teensy Mouse: set_buttons(left, middle, right, back, forward) sends a report itself. */
            uint8_t b = r.buttons;
            Mouse.set_buttons(b & 1, (b >> 2) & 1, (b >> 1) & 1, (b >> 3) & 1, (b >> 4) & 1);
            sent_buttons = b;
            out_count++;
        }

        int x = r.x, y = r.y, w = r.w, h = r.h;
        while (x != 0 || y != 0 || w != 0 || h != 0) {
            int8_t sx = clamp8(x), sy = clamp8(y), sw = clamp8(w), sh = clamp8(h);
            Mouse.move(sx, sy, sw, sh);
            out_count++;
            x -= sx; y -= sy; w -= sw; h -= sh;
        }
    }

    uint32_t now = millis();
    if (now - window_start >= 1000) {
        uint32_t in = in_reports, em = in_empty, mg = in_merged;
        uint32_t in_count = in - last_in, empty = em - last_empty, merged = mg - last_merged;
        last_in = in; last_empty = em; last_merged = mg;
        if (in_count > peak_in) peak_in = in_count;

        static const char *speeds[] = {"full-12M", "low-1.5M", "high-480M"};
        int sp = mouse1.speed();
        const uint8_t *prod = mouse1.USBHIDInput::product();
        Serial.printf("in=%lu/s empty=%lu moving=%lu out=%lu/s merged=%lu q_max=%lu peak_in=%lu link=%s product=%s\n",
                      in_count, empty, in_count - empty, out_count, merged, q_max, peak_in,
                      (sp >= 0 && sp <= 2) ? speeds[sp] : "none", prod ? (const char *)prod : "?");
        out_count = 0; q_max = 0;
        window_start = now;
    }
}
