#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mininet.term import makeTerms
from mininet.topo import Topo

class MyTopo(Topo):
    def build(self):
        # 6 switches
        switches = [self.addSwitch(f's{i}') for i in range(1, 7)]
        # 18 hosts
        hosts = [self.addHost(f'h{i}') for i in range(1, 19)]
        # Simple mapping: 3 hosts per switch
        for i, h in enumerate(hosts):
            self.addLink(h, switches[i % 6])

def run():
    net = Mininet(topo=MyTopo(), controller=None, autoSetMacs=True)
    c0 = net.addController('c0', controller=RemoteController,
                           ip='192.168.56.5', port=6633)
    net.start()

    # Choose victims and attackers
    victims = ['h2', 'h4', 'h6']
    attackers = ['h7', 'h8', 'h9', 'h10']

    # Build hping3 command for each attacker
    commands = {}
    for atk in attackers:
        cmds = []
        for v in victims:
            dst_ip = net.get(v).IP()
            # Pre-fill a UDP flood command (press Enter inside xterm to start)
            cmds.append(f"hping3 --flood --udp -p 80 {dst_ip}")
        commands[atk] = " ; ".join(cmds)

    info("*** Opening xterms for attackers\n")
    makeTerms([net.get(a) for a in attackers],
              cmd="bash --rcfile <(echo 'echo Type command below to start attack; echo')",
              term="xterm")

    # Optional: print ready-to-run commands to console for convenience
    for a, cmd in commands.items():
        print(f"{a}: {cmd}")

    info("*** Network running – use the xterm windows to launch hping3\n")
    net.interact()   # or CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
