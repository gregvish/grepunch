# grepunch
## A tool for GRE hole punching

_Warning_: This won't work for all NATs. (Only for some subset of symmetric NATs). So far only few have been tested, but most worked.

This tool enables direct peer-to-peer communication between 2 machines, each located behind a different **Symmetric NAT**, if both NATs support GRE traffic.
The various types of NAT are described here: https://en.wikipedia.org/wiki/Network_address_translation#Methods_of_translation

The intent is to provide a similar method to _UDP hole punching_ (https://en.wikipedia.org/wiki/UDP_hole_punching), which works for traversing the less restrictive NATs (i.e. "restricted-cone NAT").

Symmetric NAT, aka "bi-directional NAT" is the most restrictive NAT. Each TCP/UDP session though the NAT is identified by its _full 4-tuple_. Meaning that it's impossible for 2 machines located behind different symmetric NATs to establish a peer-to-peer UDP session without simultaneously guessing **both** UDP source/dest ports (a 1/(2**32) chance), even with the assistance of a STUN server.

This kind of NAT is generally used by large or corporate networks. Specifically, large _carrier-grade NATs_, as used by mobile networks, seem to use it almost exclusively.

## IP protocols supported by NATs

By design, NATs easily support TCP and UDP sessions, since each session can be identified by their _source/dest ports_ as well as _source/dest IPs_. However, there are other IP protocols that can traverse a NAT, for instance ICMP.

ICMP packets don't have any "port" fields, however, each ICMP request and reply share a 16 bit ID field which must be the same in the request and response. A NAT uses this field as a kind of "port" that allows it to distinguish between different ICMP sessions, even if they both have the same souce/dest IPs.

## GRE over NAT

GRE is an IP protocol designed to allow tunneling traffic encapsulated over IP. The main one of its very few uses is _PPTP_ (https://en.wikipedia.org/wiki/Point-to-Point_Tunneling_Protocol), which is a rather dated VPN protocol. It used to be fairly popular until recent years, mainly used in order to remote into corporate networks. It is still supported by modern devices and OSs out of the box.

PPTP uses a TCP connection (port 1723) for control packets, and a GRE tunnel for the encapsulated data. 

Unlike TCP, UDP or ICMP, the GRE header has very little fields. In fact, there isn't any field that can be used by NATs in order to distinguish one "session" from another. The endpoints of a GRE session are identified only by their source and dest IP. Unsurprisingly, this is difficult for NATs to handle, _and many of them do not_.
However, since the PPTP protocol was rather improtant for the corporate types, there was likely enough pressure to support it where possible. This seems to be especially true of the carrier-grade NATs, since otherwise customers of mobile carriers could not have possibly used PPTP.
