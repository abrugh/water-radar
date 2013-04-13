water-radar
===========

A utility to use your computer as a head unit for your boat's sonar

## Background ##
A friend of mine (that I'll mention by username/name once he registers for
github) is an avid fisherman, also a nerd. He noticed that the cabling to wire 
his boat's fancy sonar/depth-finder/fish-finder used what appeard to be 
standard cat-5. Curious and risk taking, he plugged his laptop in and fired up
wireshark. Packets appeared!

He told me about it and I had to twist his arm to send me a copy of the pcap.
I have some experience from my job in pulling apart mystery protocols and this
seemed like a fun, off the clock project I could work on. I had been playing 
with pygame a few months prior to this and I had a demo whipped up in a day or
two.

This all happened in the spring of 2011. I'm not a fisherman and I don't live
anywhere near my friend who is, so development hasn't happend lately.

## DISCLAIMER ##
I'm not responsible for any laptops or fishing related equipment that might 
be damaged if you plug them into each other.

## Compatibility ##
* Lowrance compatible with the HDS7 units

## Features ##
For this inital commit only the following are available:
* Reading from a pcap file
* Displaying the two side sonars and the straight down view

## Road Map ##
Features I plan on adding:
* Ability to read right off the wire
* Find other data I think is in the stream
 * Speed, location (may come from gps unit and not in on the wire)
 * Depth data
* Buttons (that emulate actual head-unit buttons)

## Dependencies ##
Neale Pickett over at dirtbags.net wrote a dead-simple pcap reader that I use.
He only has 1.0 from 2008 linked but I think I've been developing against with
a snapshot from 2011.
 
## Bugs ##
Right now this is just the inital check-in, there are many, many things wrong.
