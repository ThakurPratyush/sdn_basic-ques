from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   link=TCLink, #must be added in order to change link  parameters eg. bw,delay etc.
                   build=False,
                   ipBase='10.0.0.0/8'
                   )

    info( '* Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '* Add switches\n')
    s1 = net.addSwitch('s1',cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)
    info( '* Add hosts\n')
    h1 = net.addHost('h1',cls=Host,ip='10.0.0.1',defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)

    info( '* Add links\n')

    net.addLink(h1, s1,port1=1,port2=2,bw=20,delay='2ms',loss =0)
    net.addLink(h2, s1,port1=1,port2=3,bw=20,delay='1ms',loss=10)
    net.addLink(s1, s2,port1=4,port2=5,bw=20,delay='5ms',loss=0)
    net.addLink(s1, s3,port1=6,port2=5,bw=20,delay='3ms',loss=0)
    net.addLink(s2, s4,port1=6,port2=7,bw=20,delay='5ms',loss=0)
    net.addLink(s3, s4,port1=6,port2=8,bw=20,delay='3ms',loss=0)
    net.addLink(s4, h3,port1=2,port2=1,bw=20,delay='2ms',loss = 0)
    net.addLink(s4, h4,port1=3,port2=1,bw=20,delay='1ms',loss = 0)

    info( '* Starting network\n')

    net.build()
    info( '* Starting controllers\n')

    for controller in net.controllers:
        controller.start()

    info( '* Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])

    info( '* Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
