#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import subprocess
import sys
import time
import signal
import os
# starts a mininet testbed for switch proxy. 


def simpleNet():                                                                                                                             
    """
    <h1> ---------------------- <Forwarding Engine (s1)> -------------- <h2>
                                |           |
                            <OVS Agent>     |
                                |           |
                 <control path> |           | <fast path>           
                                |           |
                                < switch proxy (spawned outside of this script) >
                                |                
                            <controller>
    """
    print ("spawning switches.")
    net = Mininet( autoStaticArp=True )

    # spawn a switch and some hosts. 
    s1 = net.addSwitch("s1") 
    h1 = net.addHost( 'h1', ip='10.1.1.1', mac='00:00:00:00:00:01')
    h2 = net.addHost( 'h2', ip='10.1.1.2', mac='00:00:00:00:00:02')
    
    # connect hosts to switch.     
    net.addLink( h1, s1 )                                                                                                                   
    net.addLink( h2, s1 )                                                                                                                   

    print ("Starting network.")
    net.start()

    # configure switch to connect with proxy. (must be done after start)
    configSwitchForProxy('s1')

    # configure switch to clone all packets to proxy.
    # The proxy should control what goes to its fast path, eventually.
    cloneAllToProxy('s1')

    # start the proxy. 


    print ("opening CLI.")
    CLI( net )

    print ("shutting network down.")
    net.stop()

    cleanupVeths()

def configSwitchForProxy(switchName):
    """
    configure switch to connect with proxy. 
    Sets up the fastpath port on the switch. 
    Gives the proxy a table on the switch's FE.
    """
    # enable all OF protocols.
    cmd = 'sudo ovs-vsctl set bridge %s protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13'%(switchName)
    subprocess.Popen(cmd, shell=True)

    # set the switch's controller to the switchproxy port. (instead of 6633)
    # (eventually, the proxy should do this reconfiguration itself).
    cmd = 'sudo ovs-vsctl set-controller %s tcp:127.0.0.1:%s'%(switchName, 9999)
    subprocess.Popen(cmd, shell=True)

    # add a virtual eth to the switch for the proxy fastpath port.
    # the proxy should connect to ofxveth1 for the fast path.
    cmd = "sudo ip link add ofxveth0 type veth peer name ofxveth1"
    subprocess.Popen(cmd, shell=True)
    time.sleep(.1)    
    cmd = "sudo ifconfig ofxveth0 up promisc"
    subprocess.Popen(cmd, shell=True)
    time.sleep(.1)    
    cmd = "sudo ifconfig ofxveth1 up promisc"
    subprocess.Popen(cmd, shell=True)

    cmd = "sudo ovs-vsctl add-port %s ofxveth0 -- set Interface ofxveth0 ofport_request=666"%switchName
    subprocess.Popen(cmd, shell=True)

    # set up table 0 as the proxy's table. 
    cmd = """sudo ovs-ofctl add-flow %s "table=0,actions=goto_table:1" """%switchName
    subprocess.Popen(cmd, shell=True)

def cloneAllToProxy(switchName):
    # sets proxy to get a copy of all packets. Proxy should be able to add this rule itself.
    cmd = """sudo ovs-ofctl add-flow %s "table=0,actions=666,goto_table:1" """%switchName
    subprocess.Popen(cmd, shell=True)

    print ("flows on switch %s"%switchName)
    cmd = """sudo ovs-ofctl dump-flows %s """%switchName
    os.system(cmd)

def cleanupVeths():
    # cleanup: delete veth pair. 
    cmd = "sudo ip link delete ofxveth0"
    subprocess.Popen(cmd, shell=True)

if __name__ == '__main__':
    simpleNet()