```from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSKernelSwitch, Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time

class SimpleTopo(Topo):
    def build(self):
        # Add a single switch
        switch = self.addSwitch('s1')

        # Add hosts
        victim = self.addHost('h1')
        normal = self.addHost('h2')
        attackers = [self.addHost(f'h{i}') for i in range(3, 8)]  # h3 to h7 are attackers

        # Connect hosts to switch
        self.addLink(victim, switch)
        self.addLink(normal, switch)
        for attacker in attackers:
            self.addLink(attacker, switch)

def generate_traffic(net):
    victim = net.get('h1')
    normal = net.get('h2')
    attackers = [net.get(f'h{i}') for i in range(3, 8)]

    info("*** Generating normal traffic...\n")
    normal.cmd('ping -c 5 10.0.0.1 &')

    time.sleep(3)

    info("*** Starting DDoS attack using hping3...\n")
    for attacker in attackers:
        attacker.cmd(f'hping3 -S --flood -p 80 10.0.0.1 &')  # SYN flood

    info("*** Wait 10 seconds during DDoS attack...\n")
    time.sleep(10)

    info("*** Stopping all hping3 processes...\n")
    for attacker in attackers:
        attacker.cmd('killall hping3')

def run():
    topo = SimpleTopo()
    net = Mininet(topo=topo, switch=OVSKernelSwitch, controller=Controller)
    net.start()
    info("*** Network started\n")

    generate_traffic(net)

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
```
