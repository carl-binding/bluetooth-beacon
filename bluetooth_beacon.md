# Corona Exposure Tracking

It is February 2020. Skiing in the Swiss Alps is great fun, yet rumors of Corona virus making its way into Italy augment. Will Switzerland close its borders? can you lock-down a whole country in Europe? 

The virus hits canton Graubünden. Two Italian kids are infected. The Swiss authorities start to react. Crowd events are canceled in Graubünden. A week later in Switzerland crowds of more than 1'000 are banned (inclusive skiing...) and yet another week later a lock-down is imposed on Switzerland. Resta à casa - stay at home.

Rumors of a corona virus tracking app starts to appear. Simple idea: track mobile phones of people one comes into contact with. This would allow to re-constitute infection spreading. Assuming of course, the technology can be made to work, people consent to use it, and don't leave their phones at home (or have them turned off), and radio-signals can travel freely.

What does a computer scientist do in these days of confinement? reads up about Bluetooth. Figures out that there is Bluetooth BR/EDR and the newer, power-efficient, [Bluetooth Low Energy](https://en.wikipedia.org/wiki/Bluetooth_Low_Energy) also known as BLE. For which there are [3'500 pages](https://www.bluetooth.com/specifications/bluetooth-core-specification/).

Great. Wouldn't it be possible to use this stuff somehow? After all, I have a Linux box which has a Bluetooth hardware. And not really being an Android app programmer, nor having a spare Android (or iOS) phone to experiment with BLE on the phone, off we go to explore the Bluetooth LE environment on Linux/Ubuntu.

The troubles start. There is no pleasant to use Java package, it seems - unlike [JSR82](https://www.jcp.org/en/jsr/detail?id=82). One stumbles onto the [bluez](http://www.bluez.org/). Looks like what we are looking for, but the documentation is - to remain polite - sparse. The WWW informs the searching soul "read the source code". Come on, I'm too lazy for that, plus I do want to work in Java and not plain C. 

But one starts to get the hang of things, mastering all the command line utilities needed to use the Linux BLE stack.

## Things start to be interesting 

The press reports on efforts to build a Corona virus tracking app. South-Korea and Singapore seem to have something. The Europeans start big discussions on privacy, on centralized vs. de-centralized architectures for a corona tracking protocol.

One starts to wonder: where is the problem? there is enough knowledge on anonymization and cryptography which should allow to design a reasonable, privacy preserving, protocol. Some research groups start to publish such protocols. The Swiss Institutes of Technology put out a [white paper](https://github.com/DP-3T/documents/blob/master/DP3T%20White%20Paper.pdf) with a protocol proposal. 

A European consortium is borne: [PEPP-PT](https://www.pepp-pt.org/) has a great web-page with little content. The press reports on privacy discussions between the proponents of a centralized approach (the French and German authorities at the forefront) versus a de-centralized architecture (the Swiss plus some other researchers).

The chorus of protocol proposal increases. University of Washington proposes the [PACT](https://news.cs.washington.edu/2020/04/08/privacy-and-the-pandemic-uw-researchers-present-a-pact-for-using-technology-to-fight-the-spread-of-covid-19/) protocol. To the security and crypto layman this looks reasonable. 

But what about the big players? the ones that actually build smart-phone software? Google! Apple! Shouldn't they get into the fray? 

Eventually they do. And they publish a specs. A [specs](https://blog.google/inside-google/company-announcements/apple-and-google-partner-covid-19-contact-tracing-technology/) which comprises, in a concise style, details on the cryptographic token generations and how to format Bluetooth Low Energy packets. Plus some thoughts on back-end implementations. The first version is replaced with a somewhat more sophisticated version which claims better privacy protection - and is a tad harder to implement. (Currently version 1.1)

Research done. Time to implement.

There start to be some prototypes. The University of Washington and Microsoft build [CovidSafe](https://covidsafe.cs.washington.edu/) - a prototype. The Swiss software company Ubique advertises their [NextStep](https://next-step.io/de/) prototype (which incidentally reminds us of Steve Jobs' *NeXT* computer running *NextStep*).

## The tinkering in lock-down

Amazon delivers the book on Bluetooth LE:[Getting Started with Bluetooth Low Energy: Tools and Techniques for Low-Power Networking](http://shop.oreilly.com/product/0636920033011.do) which is intended to ease the learning pain. But, alas, as so often the book is hardly worth the money. Not enough details, a reasonable overview though - which helps to plow through that 3'500 pages Bluetooth specs.

A software project is started with the aim to explore the Bluetooth LE technology on my Linux box, using whatever it takes to beam out BLE beacons.

Sounds not too complicated but it is tedious. The bluez command line tools warrant invocation from the command line. The BLE data formats require tedious Java coding and, in more cases than desired, bit fiddling.

The WWW has enough information on Apple's [iBeacon](https://en.wikipedia.org/wiki/IBeacon) is popular in the Linux/Raspberry world. There even are Python scripts and other information can be found on the WWW to cobble together iBeacon advertising payloads. And there are plenty of scanners for the Android platform.

So we start to build a *beacon* which alternatively sends out BLE advertisements or scans for incoming BLE advertisement. Sounds simple and, conceptually, it is. But pitfalls are plenty:

- bit fiddling: BLE uses LSB serialization. Not all data is byte aligned and bit fiddling in Java is not as in C....
- scanning for incoming traffic: the WWW points us to hcidump in conjunction with hcitool. Great, but I want to run this from my Java beacon. So, hours are invested in building shell-scripts to be invoked from Java and which cleanly start and terminate processes and sub-processes needed in scanning for BLE advertisements. Programming shell scripts has never been a forte...
- hcidump can write to a binary file. That then needs to be parsed. More byte fiddling and parsing the BLE packet structures. Java turns out not to be the very best for low-level protocol implementations, it seems. No C struct-union overlays....  
- Linux security: the bluez command line tools require sudo privileges. To avoid password prompting in those scripts needed to use the BLE stack the Linux configs have to be tweaked. Sounds easy and, yes, it is: but it helps to put the relevant lines into the *right* place in */etc/sudoers*. And do use *visudo* - although one can still screw up the configs and then things can go pretty bad....
- the crypto was manageable. I found an implementation of [HKDF](/https://github.com/patrickfav/hkdf), which worked like a charm. AES and SHA come along with Java crypto APIs - all quite useable.
- The specs require a key-store for temporary exposure keys in order to identify exposures. For the time being, an in-secure file will do.
- After (or during) scanning, detected advertisements should be detected and safely stored away. 

