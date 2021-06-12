from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

log = core.getLogger()
def _handle_ConnectionUp(event):

  print "ConnectionUp:"
#######################################################################################switch 1

#called when switch 1 is identified
  
def s1(event):
     
     ip1=IPAddr("10.0.0.1")
     ip2=IPAddr("10.0.0.2")
     ip3=IPAddr("10.0.0.3")
     ip4=IPAddr("10.0.0.4") 

      ## arp rule for connection establishment

     rule = of.ofp_flow_mod()
     rule.idle_timeout=0
     rule.hard_timeout=0
     # discover arp packet 0x0806
     rule.match.dl_type = 0x0806
     rule.priority = 5
     rule.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
     event.connection.send(rule)

     ## ip packet rules

     #rule1 => http traffic from h1 to h4 is via s2
     r1 = of.ofp_flow_mod()
     r1.match.dl_type = 0x0800
     r1.idle_timeout = 0
     r1.hard_timeout = 0
     #source and destination matched
     r1.match.nw_src = ip1
     r1.match.nw_dst = ip4
     #for tcp based traffic
     r1.match.nw_proto = 6
     #to idenfify the http traffic
     r1.match.tp_dst = 80
     r1.actions.append(of.ofp_action_output(port = 4))
     r1.priority =8
     event.connection.send(r1)



     #rule 2 => drop packets from h1 to h3
     
     r2 = of.ofp_flow_mod()
     r2.priority =9
     #0x800 for ip packets
     r2.match.dl_type = 0x0800
     r2.idle_timeout = 0
     r2.hard_timeout = 0
     r2.match.nw_src = ip1
     r2.match.nw_dst = ip3
     # here we did not append any rule so it is blocked automatically
     event.connection.send(r2)



     #rule3 =>nonhttp traffic from h1 to h4 via switch3

     r3 = of.ofp_flow_mod()
     r3.match.dl_type = 0x0800
     r3.match.nw_src = ip1
     r3.match.nw_dst = ip4
     r3.idle_timeout = 0
     r3.hard_timeout = 0
     #directed to port toward switch3
     r3.actions.append(of.ofp_action_output(port = 6))
     r3.idle_timeout = 0
     r3.hard_timeout = 0
     r3.priority = 7
     event.connection.send(r3)

     # rule 4 => if distination is h2  
     r4 = of.ofp_flow_mod()
     r4.idle_timeout = 0
     r4.hard_timeout = 0
     r4.match.dl_type = 0x0800
     r4.match.nw_dst = ip2
     r4.priority = 10
     r4.actions.append(of.ofp_action_output(port = 3))
     event.connection.send(r4)

     # rule5=> data for h1 
     r5 = of.ofp_flow_mod()
     r5.match.dl_type = 0x0800
     r5.match.nw_dst = ip1
     r5.idle_timeout=0
     r5.hard_timeout=0
     r5.priority = 12
     r5.actions.append(of.ofp_action_output(port = 2))
     event.connection.send(r5)

     #rule 6 =>  from h2 to h4 we send via s3 shortest path traffic also here we have the least delay as per topology
     #switch3 port6
     r6 = of.ofp_flow_mod()
     r6.match.dl_type = 0x0800
     r6.idle_timeout = 0
     r6.hard_timeout = 0
     r6.match.nw_src = ip2
     r6.match.nw_dst = ip4
     r6.actions.append(of.ofp_action_output(port = 6))
     r6.priority = 11
     event.connection.send(r6)


     # rule 7 => h2 to h3 via s3
     # for shortest path
     r7 = of.ofp_flow_mod()
     r7.idle_timeout = 0
     r7.hard_timeout = 0
     r7.match.dl_type = 0x0800
     r7.match.nw_src = ip2
     r7.match.nw_dst = ip3
     r7.priority = 6
     r7.actions.append(of.ofp_action_output(port = 6))
     event.connection.send(r7)
#########################################################################################switch2

# when switch 2 is identified
def s2(event):
    
     # rule1 => from left port to right port
     ip1=IPAddr("10.0.0.1")
     ip2=IPAddr("10.0.0.2")
     ip3=IPAddr("10.0.0.3")
     ip4=IPAddr("10.0.0.4") 

     ##ip rules for switch 2

     # rule 1 ip packets from port 5 to port 6
     r1 = of.ofp_flow_mod()
     r1.match.in_port=5
     r1.idle_timeout = 0
     r1.hard_timeout = 0
     r1.actions.append(of.ofp_action_output(port = 6))
     r1.priority=2
     event.connection.send(r1)
     
     # rule2 ip from port 6 to port 5     
     r2 = of.ofp_flow_mod()
     r2.match.in_port = 6
     r2.priority=1
     r2.idle_timeout = 0
     r2.hard_timeout = 0
     r2.actions.append(of.ofp_action_output(port = 5))
     event.connection.send(r2)


#######################################################################################switch3
# when switch 3 is identified
def s3(event):
     ip1=IPAddr("10.0.0.1")
     ip2=IPAddr("10.0.0.2")
     ip3=IPAddr("10.0.0.3")
     ip4=IPAddr("10.0.0.4") 

     ##ip packet rules

     #rule 1 from port 5 to port 6
     r1 = of.ofp_flow_mod()
     r1.priority=1
     r1.match.in_port = 5
     r1.actions.append(of.ofp_action_output(port = 6))
     r1.idle_timeout=0
     r1.hard_timeout=0
     event.connection.send(r1)

     #rule2 from port 6 to port 5
     r2 = of.ofp_flow_mod()
     r2.priority=2
     r2.idle_timeout=0
     r2.hard_timeout=0
     r2.match.in_port=6
     r2.actions.append(of.ofp_action_output(port = 5))
     event.connection.send(r2)



##################################################################33switch 4
     
def s4(event):
     ip1=IPAddr("10.0.0.1")
     ip2=IPAddr("10.0.0.2")
     ip3=IPAddr("10.0.0.3")
     ip4=IPAddr("10.0.0.4") 

     ##arp rule
     rule = of.ofp_flow_mod()
     rule.idle_timeout=0
     rule.hard_timeout=0
     rule.match.dl_type = 0x0806
     rule.priority = 6
     rule.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
     event.connection.send(rule)
     
     ##ip packet rules


     #rule 1 => h4 to h1 via switch2 http traffic
     r1 = of.ofp_flow_mod()
     r1.match.dl_type = 0x0800
     r1.idle_timeout = 0
     r1.hard_timeout = 0
     r1.match.nw_src = ip4
     r1.match.nw_dst = ip1
     #identify tcp protocol
     r1.match.nw_proto = 6     
     r1.match.tp_dst = 80 
     r1.actions.append(of.ofp_action_output(port = 7))
     r1.priority = 8
     event.connection.send(r1)


     #rule2 => h4 to h1 non http via s3
     r2 = of.ofp_flow_mod()
     r2.match.dl_type = 0x0800
     r2.match.nw_src = ip4
     r2.match.nw_dst = ip1
     r2.actions.append(of.ofp_action_output(port = 8))
     r2.idle_timeout = 0
     r2.hard_timeout = 0
     r2.priority = 7
     event.connection.send(r2)

     #rule3 blocking from h3 to h1
     r3 = of.ofp_flow_mod()
     r3.match.dl_type = 0x0800
     r3.idle_timeout = 0
     r3.hard_timeout = 0
     r3.match.nw_src = ip3
     r3.match.nw_dst = ip1
     r3.priority = 14
     event.connection.send(r3)



     # rule 4 packets for h4 sent from s4 to port 3
     r4 = of.ofp_flow_mod()
     r4.match.dl_type = 0x0800
     r4.match.nw_dst = ip4
     r4.priority = 12
     r4.actions.append(of.ofp_action_output(port = 3))
     event.connection.send(r4)

     # rule 5 for host 3 port 2 
     r5 = of.ofp_flow_mod()
     r5.idle_timeout=0
     r5.hard_timeout=0
     r5.match.dl_type = 0x0800
     r5.match.nw_dst =ip3
     r5.priority = 11
     r5.actions.append(of.ofp_action_output(port = 2))
     event.connection.send(r5)


     #rule 6 h3 to h2 via switch 3 for shortest path
     r6 = of.ofp_flow_mod()
     r6.idle_timeout = 0
     r6.hard_timeout = 0
     r6.match.dl_type = 0x0800
     r6.match.nw_src = ip3
     r6.match.nw_dst = ip2
     r6.priority = 5
     r6.actions.append(of.ofp_action_output(port = 7))
     event.connection.send(r6)

     #rule7 4 to 2 via s3 for shortest path
     r7 = of.ofp_flow_mod()
     r7.match.dl_type = 0x0800
     r7.hard_timeout=0
     r7.idle_timeout= 0
     r7.match.nw_src = ip4
     r7.match.nw_dst = ip2
     r7.actions.append(of.ofp_action_output(port = 7))
     r7.priority = 10
     event.connection.send(r7)



#packet in event
def _handle_PacketIn(event):

     if event.dpid == 1:
          s1(event)

     elif event.dpid == 2:
          s2(event)

          
     elif event.dpid == 3:
          s3(event)


     elif event.dpid == 4:
          s4(event)

          
          
          
def start_switch(event):
    log.debug(dpidToStr(event.connection.dpid))

def launch ():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn",  _handle_PacketIn)
