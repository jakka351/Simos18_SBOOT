#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate two 3.2 kHz square waves with ~90° phase offset using pigpio wave DMA.

Pin A: GPIO17 (BCM)
Pin B: GPIO27 (BCM)

Period: 312.5 µs (3.2 kHz). 50% duty.
Phase: B lags A by ~78.125 µs (quarter period).

You can tweak pins with --pin-a / --pin-b.
Ctrl+C to stop.

Requires: sudo apt install pigpio ; sudo systemctl start pigpiod
"""
from __future__ import annotations
import argparse
import pigpio
import time
import sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin-a", type=int, default=17)
    ap.add_argument("--pin-b", type=int, default=27)
    ap.add_argument("--freq", type=float, default=3200.0, help="Hz (default 3200)")
    args = ap.parse_args()

    period_us = int(round(1_000_000.0 / args.freq))
    half_us = period_us // 2
    quarter_us = period_us // 4  # 78.125us at 3.2kHz -> 78us; pigpio rounds to µs

    pi = pigpio.pi()
    if not pi.connected:
        print("pigpio not running (sudo systemctl start pigpiod)", file=sys.stderr)
        sys.exit(1)

    A = args.pin_a; B = args.pin_b
    for pin in (A, B):
        pi.set_mode(pin, pigpio.OUTPUT)
        pi.write(pin, 0)

    # Wave 0: A high half-period, low half-period. B lags by quarter-period.
    # We build a repeating chain: A rises now; after quarter_us, B rises; after half, A falls; after quarter, B falls.
    wf = []
    # Step 1: A rises
    wf.append(pigpio.pulse(1<<A, 0, 0))
    # Step 2: wait quarter -> then B rises
    wf.append(pigpio.pulse(0, 0, quarter_us))
    wf.append(pigpio.pulse(1<<B, 0, 0))
    # Step 3: wait half -> then A falls
    wf.append(pigpio.pulse(0, 0, half_us))
    wf.append(pigpio.pulse(0, 1<<A, 0))
    # Step 4: wait quarter -> then B falls (period complete)
    wf.append(pigpio.pulse(0, 0, quarter_us))
    wf.append(pigpio.pulse(0, 1<<B, 0))

    pi.wave_add_generic(wf)
    wid = pi.wave_create()
    if wid < 0:
        print("wave_create failed", file=sys.stderr); sys.exit(2)

    # Transmit continuously
    pi.wave_send_repeat(wid)
    print(f"Running: A=GPIO{A}, B=GPIO{B}, f≈{args.freq:.1f} Hz, T={period_us}us, phase≈{quarter_us}us")
    print("Ctrl+C to stop")
    try:
        while pi.wave_tx_busy():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        pi.wave_tx_stop()
        pi.wave_clear()
        pi.stop()

if __name__ == "__main__":
    main()
