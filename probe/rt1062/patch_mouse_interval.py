# Pre-build: make the Teensy core's USB_SERIAL_HID mouse endpoint poll every high-speed
# microframe (bInterval 1 = 125 us = 8 kHz) instead of the stock 2 (250 us = 4 kHz).
# Patches the cached framework in place, idempotently, only inside the USB_SERIAL_HID block.
Import("env")
import os, re

core = env.PioPlatform().get_package_dir("framework-arduinoteensy")
path = os.path.join(core, "cores", "teensy4", "usb_desc.h")
src = open(path, encoding="utf-8").read()

start = src.index("defined(USB_SERIAL_HID)")
end = src.index("#elif", start)
block = src[start:end]
patched = re.sub(r"(#define MOUSE_INTERVAL\s+)\d+", r"\g<1>1", block)
if patched != block:
    open(path, "w", encoding="utf-8").write(src[:start] + patched + src[end:])
    print("patch_mouse_interval: USB_SERIAL_HID MOUSE_INTERVAL -> 1 (8 kHz at high speed)")
