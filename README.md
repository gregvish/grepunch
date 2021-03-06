# grepunch
## A tool for GRE hole punching

_Warning_: This won't work for all NATs (only for some subset of symmetric NATs). So far only few have been tested, but most worked.

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

Unlike TCP, UDP or ICMP, the default (v0) GRE header has very little fields. In fact, there isn't any field that can be used by NATs in order to distinguish one "session" from another. The endpoints of a GRE session are identified only by their source and dest IP. Unsurprisingly, this is difficult for NATs to handle, _and many of them do not_.
However, since the PPTP protocol was rather improtant for the corporate types, there was likely enough pressure to support it where possible. This seems to be especially true of the carrier-grade NATs, since otherwise customers of mobile carriers could not have possibly used PPTP.

A symmetric NAT identifies each GRE session by _both_ source and dest IPs. Therefore, a machine behind a NAT can connect to multiple *different* internet IPs. Multiple machines behind the same NAT can connect to *different* internet IPs. However, multiple machines behind the same NAT can't connect to the *same* internet IP. Therefore GRE behind a symmetric NAT will only "mostly" work.

## Using GRE for NAT traversal

Since a GRE session is identified only by souce/dest IPs, there are no additional identifiers to guess in order to "punch a hole" through the NAT. The only requirement is knowing *both* external IPs of the NATs by both parties in advance (much like _UDP hole punching_).

Asume the following scenario. Alice and Bob have internal IP addresses behind symmetric NATs:

`Alice -- NAT_A <-------> NAT_B -- Bob`

1) Alice sends a GRE packet to the IP of NAT_B. This makes NAT_A pass the packet to NAT_B, and configures NAT_A to pass any incoming GRE packet _from_ NAT_B to Alice.
2) NAT_B receives this unsolicited GRE packet and drops it.
3) Bob sends a GRE packet to the IP of NAT_A. This makes NAT_B pass the packet to NAT_A, and configures NAT_B to pass any incoming GRE packet _from_ NAT_A to Bob.
4) This packet arrives at NAT_A, which will now pass this packet to Alice due to step 1.
5) Bidierectional comms have been established!

## Limitations

Apart from the obvious issue of some NATs not supporting GRE at all, there are additional limitations:
1) 2 different machines behind NAT_A can't, **at the same time**, communicate with a machine behind NAT_B.
2) If Alice and Bob are behind the **same** NAT (i.e., on the same external carrier-NAT IP), they can't communicate.

## Tool requirements

* Python 3
* `sudo pip3 install pytap2`
* `sudo pip3 install python-daemon`

## Using this tool

Usage: `sudo python3 grepunch.py <PEER_NAT_IP>`
This must run as root since it uses raw sockets, and creates a TUN device.

Using something like `curl icanhazip.com`, on each machine, determine the NAT_A and NAT_B IPs for both machines. Then, on each machine, run `sudo python3 grepunch.py <NAT_B/A>` respectively.

By default, this will create a _tun0_ interface with a special 169.254.100.1 IP on *both* machines. This IP will represent the *other peer* for each machine. 

A realistic usage for this is:
1) Knowing 1 of the IPs in advance (let's say, NAT_A).
2) While being present at machine B, launch the tool with the IP of NAT_A. Also, learn the IP of NAT_B.
3) At some later time, when finally present at machine A, launch the tool with the IP of NAT_B.

## Why is this useful

There are many uses cases for peer-to-peer comms without a mediating 3rd party server. However, the most improtant one (for me at least) is latency reduction. Using this tool, one can SSH between 2 machines behind NATs directly, without the additional latency of an intermediate server.

## Security implications

This tool simply exposes your internal machine _directly_ to the internet, without authentication. This is perfectly fine if your machine merely exposes an SSH server, or any other encrypted and authenticated service. However, care must be taken not to expose plain-text or insecure services from your local machine to the internet.
