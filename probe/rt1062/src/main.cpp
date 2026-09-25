// RT1062 first-light probe.
// Mouse in the carrier's USB-A (USB2, high-speed host) -> Teensy -> USB-C (USB1, high-speed device) -> PC.
// Reports from the mouse are counted and their movement accumulated in the USB callback, then
// sent to the PC as fast as the PC polls: several in, one out = the coalescing the real firmware needs.
// Every second, prints in/out report rates over USB serial.

#include <Arduino.h>
#include <USBHost_t36.h>

class CountingMouse : public MouseController {
public:
    CountingMouse(USBHost &host) : MouseController(host) {}

    volatile uint32_t reports = 0;
    volatile int32_t  acc_x = 0, acc_y = 0, acc_w = 0, acc_h = 0;
    volatile uint8_t  buttons = 0;

    /* Negotiated link speed of the mouse on the host port: 0 = full 12 Mbit, 1 = low 1.5 Mbit, 2 = high 480 Mbit */
    int speed() { return mydevice ? mydevice->speed : -1; }

protected:
    void hid_input_end() override {
        MouseController::hid_input_end();      /* fills mouseX etc. from this one report */
        acc_x += getMouseX();
        acc_y += getMouseY();
        acc_w += getWheel();
        acc_h += getWheelH();
        buttons = getButtons();
        reports++;
        mouseDataClear();
    }
};

USBHost myusb;
USBHub hub1(myusb);
USBHIDParser hid1(myusb);
USBHIDParser hid2(myusb);
USBHIDParser hid3(myusb);
USBHIDParser hid4(myusb);
CountingMouse mouse1(myusb);

static uint32_t out_count = 0, window_start = 0, peak_in = 0, last_reports = 0;
static uint8_t last_buttons = 0;

static inline int8_t clamp8(int v) { return v > 127 ? 127 : (v < -127 ? -127 : v); }

void setup() {
    Serial.begin(115200);
    myusb.begin();
    window_start = millis();
}

void loop() {
    myusb.Task();

    /* Snapshot and clear the accumulator atomically with respect to the USB interrupt */
    __disable_irq();
    int32_t x = mouse1.acc_x, y = mouse1.acc_y, w = mouse1.acc_w, h = mouse1.acc_h;
    uint8_t b = mouse1.buttons;
    mouse1.acc_x = mouse1.acc_y = mouse1.acc_w = mouse1.acc_h = 0;
    __enable_irq();

    if (b != last_buttons) {
        /* MouseController: bit0 left, bit1 right, bit2 middle, bit3 back, bit4 forward.
           Teensy Mouse: set_buttons(left, middle, right, back, forward). */
        Mouse.set_buttons(b & 1, (b >> 2) & 1, (b >> 1) & 1, (b >> 3) & 1, (b >> 4) & 1);
        last_buttons = b;
        out_count++;
    }

    while (x != 0 || y != 0 || w != 0 || h != 0) {
        int8_t sx = clamp8(x), sy = clamp8(y), sw = clamp8(w), sh = clamp8(h);
        Mouse.move(sx, sy, sw, sh);              /* blocks until the PC takes the previous report */
        out_count++;
        x -= sx; y -= sy; w -= sw; h -= sh;
    }

    uint32_t now = millis();
    if (now - window_start >= 1000) {
        uint32_t r = mouse1.reports;
        uint32_t in_count = r - last_reports;
        last_reports = r;
        if (in_count > peak_in) peak_in = in_count;
        static const char *speeds[] = {"full-12M", "low-1.5M", "high-480M"};
        int sp = mouse1.speed();
        const uint8_t *prod = mouse1.USBHIDInput::product();
        Serial.printf("in=%lu/s out=%lu/s peak_in=%lu mouse=%04x:%04x link=%s product=%s\n",
                      in_count, out_count, peak_in,
                      mouse1.USBHIDInput::idVendor(), mouse1.USBHIDInput::idProduct(),
                      (sp >= 0 && sp <= 2) ? speeds[sp] : "none", prod ? (const char *)prod : "?");
        out_count = 0;
        window_start = now;
    }
}
