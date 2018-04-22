---
layout: post
title:  "Have a Arduino copy with CH340 chip. Need driver for OSX"
date:   2016-01-06 21:17:10 +0530
categories: arduino ch340
---

I recently starting working with an Arduino kit for BLE. But the ArduinoUno was probably as cheap copy with `CH340chip` instead of standard serial to usb chip.
In the Arduino IDE i could not find a serial port for Arduino.
Many old links online suggested installing CH340 driver which were unsigned. Since OSX Yosemite onwards Apple does not allow installation of unsigned drivers that would mean i would have to bypass this using `crutil` command in boot recover mode to install driver.

Luckily  as of nov 2015 a signed driver for CH340 chip is available which can be downloaded from [CH34x_Install.zip][ch34x-link]

[ch34x-link]: http://kig.re/downloads/CH34x_Install.zip
