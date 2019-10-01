import errno
import sys
import struct
import socket
import select
import random
import ipaddress

import pytap2


IPPROTO_GRE = 47
GRE_HEADER = bytes.fromhex('00000800')
DUMMY_PACKET = bytes.fromhex('4500001c0001000040017ae100000000000000000800f7ff00000000')
IP_HEADER_LEN = 20
IP_PROTO_OFFSET = 9
IP_CSUM_OFFSET = 10
IP_SRC_OFFSET = 12
IP_DST_OFFSET = 16
AFTER_GRE_OFFSET = IP_HEADER_LEN + len(GRE_HEADER)
TUN_MTU = 1400
FRAME_SIZE = 0xffff
KEEPALIVE_TIMEOUT = 5


def main(peer, virtual_subnet='169.254.100.0/30'):
    subnet = ipaddress.ip_network(virtual_subnet)
    local_ip = str(max(subnet.hosts()))
    peer_ip = str(min(subnet.hosts()))
    local_ip_bytes = socket.inet_aton(local_ip)
    peer_ip_bytes = socket.inet_aton(peer_ip)

    dummy_pack = bytearray(DUMMY_PACKET)
    dummy_pack[IP_SRC_OFFSET: IP_SRC_OFFSET + 4] = local_ip_bytes
    dummy_pack[IP_DST_OFFSET: IP_DST_OFFSET + 4] = peer_ip_bytes
    csum = (
        struct.unpack('>H', dummy_pack[IP_CSUM_OFFSET: IP_CSUM_OFFSET + 2])[0] -
        sum(struct.unpack('>HHHH', local_ip_bytes + peer_ip_bytes))
    )
    dummy_pack[IP_CSUM_OFFSET: IP_CSUM_OFFSET + 2] = struct.pack('>H', (csum & 0xffff) + (csum >> 16))

    gre = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_GRE)
    gre.connect((peer, 0))

    with pytap2.TapDevice() as tun:
        tun.ifconfig(mtu=TUN_MTU, address=local_ip, netmask=subnet.netmask)
        tun.up()

        gre.send(GRE_HEADER + dummy_pack)
        print('Running. Local IP for peer: %s localhost: %s' % (peer_ip, local_ip))

        while True:
            rfds, _, _ = select.select([tun, gre], [], [], KEEPALIVE_TIMEOUT)

            if not rfds:
                gre.send(GRE_HEADER + dummy_pack)
                continue

            fd = random.choice(rfds)

            if fd is tun:
                pack = tun.read(FRAME_SIZE)
                if pack[IP_DST_OFFSET: IP_DST_OFFSET + 4] != peer_ip_bytes:
                    continue
                gre.send(GRE_HEADER + pack)

            elif fd is gre:
                try:
                    pack = bytearray(gre.recv(FRAME_SIZE)[AFTER_GRE_OFFSET:])
                except OSError as e:
                    if e.errno == errno.ENOPROTOOPT:
                        print(e)
                        continue
                    elif e.errno == errno.EMSGSIZE:
                        # TODO: why?
                        continue
                    raise
                if pack[IP_PROTO_OFFSET] == socket.IPPROTO_ICMP:
                    print('Got ICMP from other side')
                pack[IP_SRC_OFFSET: IP_SRC_OFFSET + 4] = peer_ip_bytes
                pack[IP_DST_OFFSET: IP_DST_OFFSET + 4] = local_ip_bytes
                tun.write(pack)


if __name__ == '__main__':
    main(*sys.argv[1:])
