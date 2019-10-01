import argparse
import errno
import ipaddress
import logging
import struct
import socket
import select
import random
import time

import daemon
import pytap2


IPPROTO_GRE = 47
GRE_HEADER = bytes.fromhex('00000800')
KEEPALIVE_PACKET = bytes.fromhex('4500001c0001000040017ae100000000000000000800f7ff00000000')
IP_HEADER_LEN = 20
IP_PROTO_OFFSET = 9
IP_CSUM_OFFSET = 10
IP_SRC_OFFSET = 12
IP_DST_OFFSET = 16
AFTER_GRE_OFFSET = IP_HEADER_LEN + len(GRE_HEADER)
TUN_MTU = 1400
FRAME_SIZE = 0xffff
KEEPALIVE_TIMEOUT = 5


class GREPunch:
    def __init__(self, peer, virt_subnet):
        self._log = logging.getLogger(self.__class__.__name__)
        self._last_keepalive = time.monotonic()
        self._alive_state = False
        self._peer = peer

        self._subnet = ipaddress.ip_network(virt_subnet)
        self._local_ip = str(max(self._subnet.hosts()))
        self._peer_ip = str(min(self._subnet.hosts()))
        self._local_ip_bytes = socket.inet_aton(self._local_ip)
        self._peer_ip_bytes = socket.inet_aton(self._peer_ip)

        keepalive_pack = bytearray(KEEPALIVE_PACKET)
        keepalive_pack[IP_SRC_OFFSET: IP_SRC_OFFSET + 4] = self._local_ip_bytes
        keepalive_pack[IP_DST_OFFSET: IP_DST_OFFSET + 4] = self._peer_ip_bytes
        csum = (
            struct.unpack('>H', keepalive_pack[IP_CSUM_OFFSET: IP_CSUM_OFFSET + 2])[0] -
            sum(struct.unpack('>HHHH', self._local_ip_bytes + self._peer_ip_bytes))
        )
        keepalive_pack[IP_CSUM_OFFSET: IP_CSUM_OFFSET + 2] = (
            struct.pack('>H', (csum & 0xffff) + (csum >> 16))
        )
        self._keepalive_pack = keepalive_pack

    def _kick_keepalive(self, log):
        self._last_keepalive = time.monotonic()
        if not self._alive_state:
            self._log.info('Got keepalive. %s', log)
        self._alive_state = True

    def _check_keepalive(self):
        now = time.monotonic()
        if now - self._last_keepalive < 3 * KEEPALIVE_TIMEOUT:
            return
        if self._alive_state:
            self._log.warning('Keepalive missed')
        self._alive_state = False

    def _gre_to_tun(self, tun, gre):
        try:
            pack = bytearray(gre.recv(FRAME_SIZE)[AFTER_GRE_OFFSET:])

        except OSError as e:
            if e.errno == errno.ENOPROTOOPT:
                if self._alive_state:
                    self._log.warning(e)
                return
            elif e.errno == errno.EMSGSIZE:
                # TODO: why?
                return
            raise

        if pack[IP_PROTO_OFFSET] == socket.IPPROTO_ICMP:
            self._kick_keepalive('ICMP form other side')
        else:
            self._kick_keepalive('Traffic')

        pack[IP_SRC_OFFSET: IP_SRC_OFFSET + 4] = self._peer_ip_bytes
        pack[IP_DST_OFFSET: IP_DST_OFFSET + 4] = self._local_ip_bytes
        tun.write(pack)

    def _tun_to_gre(self, tun, gre):
        pack = tun.read(FRAME_SIZE)

        if pack[IP_DST_OFFSET: IP_DST_OFFSET + 4] != self._peer_ip_bytes:
            return

        gre.send(GRE_HEADER + pack)

    def _punch_and_serve_impl(self):
        gre = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_GRE)
        gre.connect((self._peer, 0))

        with pytap2.TapDevice() as tun:
            tun.ifconfig(mtu=TUN_MTU, address=self._local_ip, netmask=self._subnet.netmask)
            tun.up()

            gre.send(GRE_HEADER + self._keepalive_pack)
            self._log.info(
                'Running. Local IP for peer: %s localhost: %s' % (self._peer_ip, self._local_ip)
            )

            while True:
                rfds, _, _ = select.select([tun, gre], [], [], KEEPALIVE_TIMEOUT)

                if not rfds:
                    gre.send(GRE_HEADER + self._keepalive_pack)
                    self._check_keepalive()
                    continue

                fd = random.choice(rfds)

                if fd is tun:
                    self._tun_to_gre(tun, gre)
                elif fd is gre:
                    self._gre_to_tun(tun, gre)

    def punch_and_serve(self):
        try:
            self._punch_and_serve_impl()
        except BaseException as e:
            self._log.exception(e)
            raise


def main():
    parser = argparse.ArgumentParser(description='GRE hole pucher',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('peer', help='External IP of the peer (IP of remote NAT)')
    parser.add_argument('--virt_subnet', default='169.254.100.0/30',
                        help='Subnet for local interface with the virtual peer IP')
    parser.add_argument('--daemon', action='store_true', help='Daemonize')
    parser.add_argument('--logfile', default=None, help='Log file name')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG,
        filename=args.logfile,
        format='%(name)s: %(asctime)s %(levelname)s: %(message)s'
    )

    grepunch = GREPunch(args.peer, args.virt_subnet)

    if args.daemon:
        with daemon.DaemonContext(files_preserve=[logging.root.handlers[0].stream.fileno()]):
            grepunch.punch_and_serve()
    else:
        grepunch.punch_and_serve()


if __name__ == '__main__':
    main()
