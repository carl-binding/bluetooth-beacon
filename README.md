# Bluetooth beaconing on a Linux box

Inspired by Corona lockdowns, I have put together some Java SE code running on an [Ubuntu/Linux/bluez](http://www.bluez.org/) environment, to start playing with [Bluetooth Low Energy (BLE)](https://www.bluetooth.com/specifications/bluetooth-core-specification/) to implement such things as [Apple iBeacon](https://en.wikipedia.org/wiki/IBeacon) and, of course, due to current concerns in April 2020, a [Corona exposure notification scheme](https://blog.google/inside-google/company-announcements/apple-and-google-partner-covid-19-contact-tracing-technology/).

The code is experimental. It does not necessarily claim engineering elegance. There is very little security beyond the security inherent in the proposed Apple & Google Exposure Notification schemes.

There probably are plenty of remaining bugs, be it in the application of the crypto schemes, be it in the handling of (densely packed) BLE data formats, or whatever other error.

Interfacing to BLE on Linux using the bluez command line tools makes the whole thing ugly and brittle. I just didn't have the stomach to wade through the bluez sources, rip out the needed C code and make it Java accessible.

Clearly, in order to implement a real Corona virus exposure tracking app, much more is needed. And the implementation needs to run on Android and iOS - environments which I have not programmed against and which definitely are a change from good old UNIX.... A Linux box was all I had to play with and a feasibility prototype was the goal.

Using an USB BLE dongle might have made certain things easier. Command line bluez tools required some shell-scripting which is syntactically painful and brittle during execution. 

There now is some SQLite storage for temporary exposure keys and proximity IDs. AES encrypted exposure keys can be activated - not tested. Storage is not space optimized. There is support for purging the temp exposure keys and proximity ID stores, not really tested.

There is no support to match exposure notifications deemed positive with detected, locally stored, and health-authority published, exposure notifications. Hence also no attempt to communicate with any back-end (though it's not for lack of available technologies).

Maybe someone can benefit of this stuff, maybe not. It's not research - just some SW engineering.

It is my belief that building a Corona exposure tracking app does make sense. It is not a panacea, but it might help in tracking down exposures which, IMHO, would assist epidemiological efforts. But yes, enough people need to use such apps on their smart-phones, turn them on, not forget them at home, and hope that the contact tracing based on possibly disturbed electromagnetic waves is accurate enough.

As long as there are no widely-available, easy-to-use, and affordable testing means for Corona virus nor any vaccine against it, it might be worth to attempt contact tracing via Bluetooth LE. Privacy concerns are justified, but a sensible risk-assessment of privacy vs. public health is warranted.



