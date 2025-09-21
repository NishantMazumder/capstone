#!/usr/bin/env python3
"""
Enhanced Mininet DDoS traffic generator
Topology: 6 switches, 18 hosts
Attacks: ICMP, UDP, TCP-SYN, LAND
Adds background benign traffic and variable-rate floods
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep
from datetime import datetime
from random import randrange, choice

class MyTopo(Topo):
    def build(self):
        # switches
        s = [self.addSwitch(f"s{i}", cls=OVSKernelSwitch, protocols="OpenFlow13")
             for i in range(1, 7)]

        # 18 hosts
        hosts = []
        for i in range(1, 19):
            h = self.addHost(
                f"h{i}",
                cpu=1.0/20,
                mac=f"00:00:00:00:00:{i:02d}",
                ip=f"10.0.0.{i}/24"
            )
            hosts.append(h)
            self.addLink(h, s[(i-1)//3])

        # chain switches
        for i in range(5):
            self.addLink(s[i], s[i+1])

def ip_generator():
    return f"10.0.0.{randrange(1,19)}"

def startNetwork():
    topo = MyTopo()
    c0 = RemoteController('c0', ip='192.168.56.5', port=6633)
    net = Mininet(topo=topo, link=TCLink, controller=c0)
    net.start()

    hosts = [net.get(f"h{i}") for i in range(1,19)]

    # simple web server for benign HTTP traffic
    net.get('h1').cmd('cd /home/mininet/webserver && python3 -m http.server 80 &')

    # background benign traffic (pings & iperf)
    for _ in range(6):
        a, b = choice(hosts), choice(hosts)
        if a != b:
            a.cmd(f"ping -i 1 -c 300 {b.IP()} &")

    print("\n=== Starting DDoS Rounds ===")
    attack_types = [
        "-1",   # ICMP
        "-2",   # UDP
        "-S",   # TCP SYN
        "land"  # handled separately
    ]

    for round_num in range(6):  # six mixed rounds
        print(f"\n--- Round {round_num+1} ---")
        attackers = [choice(hosts) for _ in range(3)]
        victim = ip_generator()
        interval = choice(["u1000", "u5000", "u10000"])  # 1–10 ms
        atk_type = choice(attack_types)

        for atk in attackers:
            if atk_type == "land":
                atk.cmd(
                    f"timeout 30s hping3 -1 -d 120 -w 64 --flood -a {victim} {victim} &"
                )
            elif atk_type == "-S":
                atk.cmd(
                    f"timeout 30s hping3 {atk_type} -d 120 -w 64 -i {interval} -p 80 --rand-source {victim} &"
                )
            else:
                atk.cmd(
                    f"timeout 30s hping3 {atk_type} -d 120 -w 64 -i {interval} --rand-source {victim} &"
                )

        sleep(40)  # slight overlap of attacks

    net.stop()

if __name__ == '__main__':
    start_time = datetime.now()
    setLogLevel('info')
    startNetwork()
    print("Total time:", datetime.now() - start_time)
