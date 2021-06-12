from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.openflow.of_json import *
from pox.lib.recoco import Timer
import time
log = core.getLogger()

source_dpid1 =0
destination_dpid1=0
source_dpid2=0
destination_dpid2=0
input_packets_non_http =0
output_packets_non_http=0
input_packets_http=0
output_packets_http=0


#######################################################question 4 specific code #############################################################################
def _timer_func ():
  for connection in core.openflow._connections.values():
    connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
  log.debug("sending %i flow and port stats request(s)", len(core.openflow._connections))

# creating a time stamp
def getTheTime():  
  clock_Val = time.localtime()
  val = "[%s-%s-%s" %(str(clock_val.tm_year),str(clock_val.tm_mon),str(clock_val.tm_mday))
  if int(clock_val.tm_hour)<10:
    hours = "0%s" % (str(clock_val.tm_hour))
  else:
    hours = str(clock_val.tm_hour)
  if int(clock_val.tm_min)<10:
    minutes = "0%s" % (str(clock_val.tm_min))
  else:
    minutes = str(clock_val.tm_min)
  if int(clock_val.tm_sec)<10:
    seconds = "0%s" % (str(clock_val.tm_sec))
  else:
    seconds = str(clock_val.tm_sec)
  val +="]%s.%s.%s" % (hours,minutes,seconds)
  return val



def _handle_flowstats_received (event):
  ip1=IPAddr("10.0.0.1")
  ip4=IPAddr("10.0.0.4") 
  global source_dpid1, destination_dpid1,source_dpid2, destination_dpid2, input_packets_non_http, output_packets_non_http,input_packets_http,output_packets_http
  #counting the number of packets input in http traffic
  for flow in event.stats:
    if flow.match.dl_type == 0x0800 and flow.match.nw_dst==ip4 and (flow.match.tp_dst==80 or flow.match.tp_src==80) and event.connection.dpid==source_dpid1:
      if flow.packet_count>0:
        input_packets_http = flow.packet_count
      if flow.match.nw_dst==ip4 and (flow.match.tp_dst==80 or flow.match.tp_src==80) and event.connection.dpid==destination_dpid1:
        output_packets_http = flow.packet_count
      if input_packets_http>0:
        print "http loss =", (input_packets_http-output_packets_http)
     
  #packet loss for non http traffic
    if flow.match.nw_dst==ip4 and event.connection.dpid==source_dpid1:
      if flow.packet_count>0:
        input_packets_non_http=flow.packet_count
      if flow.match.nw_dst==ip4  and event.connection.dpid==destination_dpid1:
        output_packets_non_http = flow.packet_count
      if input_packets_non_http>0:
        print "non http loss=",(input_packets_non_http - output_packets_non_http)






########################################################### end of question 4 specific code##########################################################################################
def _handle_ConnectionUp(event):
  global source_dpid1, destination_dpid1,source_dpid2, destination_dpid2
  print "ConnectionUp: ", dpidToStr(event.connection.dpid)
  for eve in event.connection.features.ports:
    if eve.name == "s1-eth4":
      source_dpid1 = event.connection.dpid
    elif eve.name == "s4-eth7":
      destination_dpid1 = event.connection.dpid
    elif eve.name == "s1-eth6":
      source_dpid1 = event.connection.dpid
    elif eve.name == "s4-eth8":
      destination_dpid1 = event.connection.dpid
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
     rule.priority = 10
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
     r1.priority = 13
     event.connection.send(r1)



     #rule 2 => drop packets from h1 to h3
     
     r2 = of.ofp_flow_mod()
     r2.priority = 14
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
     r3.priority = 12
     event.connection.send(r3)

     # rule 4 => if distination is h2  
     r4 = of.ofp_flow_mod()
     r4.idle_timeout = 0
     r4.hard_timeout = 0
     r4.match.dl_type = 0x0800
     r4.match.nw_dst = ip2
     r4.priority = 15
     r4.actions.append(of.ofp_action_output(port = 3))
     event.connection.send(r4)

     # rule5=> data for h1 
     r5 = of.ofp_flow_mod()
     r5.match.dl_type = 0x0800
     r5.match.nw_dst = ip1
     r5.idle_timeout=0
     r5.hard_timeout=0
     r5.priority = 17
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
     r6.priority = 16
     event.connection.send(r6)


     # rule 7 => h2 to h3 via s3
     # for shortest path
     r7 = of.ofp_flow_mod()
     r7.idle_timeout = 0
     r7.hard_timeout = 0
     r7.match.dl_type = 0x0800
     r7.match.nw_src = ip2
     r7.match.nw_dst = ip3
     r7.priority = 11
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
     rule.priority = 11
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
     r1.priority = 13
     event.connection.send(r1)


     #rule2 => h4 to h1 non http via s3
     r2 = of.ofp_flow_mod()
     r2.match.dl_type = 0x0800
     r2.match.nw_src = ip4
     r2.match.nw_dst = ip1
     r2.actions.append(of.ofp_action_output(port = 8))
     r2.idle_timeout = 0
     r2.hard_timeout = 0
     r2.priority = 12
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
     r5.priority = 16
     r5.actions.append(of.ofp_action_output(port = 2))
     event.connection.send(r5)


     #rule 6 h3 to h2 via switch 3 for shortest path
     r6 = of.ofp_flow_mod()
     r6.idle_timeout = 0
     r6.hard_timeout = 0
     r6.match.dl_type = 0x0800
     r6.match.nw_src = ip3
     r6.match.nw_dst = ip2
     r6.priority = 10
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
     r7.priority = 15
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
    core.openflow.addListenerByName("FlowStatsReceived",_handle_flowstats_received)
    Timer(5, _timer_func, recurring=True)
    

    
