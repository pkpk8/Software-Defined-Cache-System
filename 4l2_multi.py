# Copyright 2012-2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A shortest-path forwarding application.

This is a standalone L2 switch that learns ethernet addresses
across the entire network and picks short paths between them.

You shouldn't really write an application this way -- you should
keep more state in the controller (that is, your flow tables),
and/or you should make your topology more static.  However, this
does (mostly) work. :)

Depends on openflow.discovery
Works with openflow.spanning_tree
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import Timer
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_dpid
import time
import threading
from socket import socket, AF_INET, SOCK_STREAM
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr, IPAddr

log = core.getLogger()

# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda:defaultdict(lambda:None))

# Switches we know of.  [dpid] -> Switch
switches = {}

# ethaddr -> (switch, port)
mac_map = {}

# [sw1][sw2] -> (distance, intermediate)
path_map = defaultdict(lambda:defaultdict(lambda:(None,None)))

# Waiting path.  (dpid,xid)->WaitingPath
waiting_paths = {}

# Time to not flood in seconds
FLOOD_HOLDDOWN = 5

# Flow timeouts
FLOW_IDLE_TIMEOUT = 10
FLOW_HARD_TIMEOUT = 30

# How long is allowable to set up a path?
PATH_SETUP_TIME = 4


#------by chen
DPID_MAC = {'00-00-00-00-00-01':'7A:58:5B:D0:5B:F4', '00-00-00-00-00-02':'62:44:F1:38:FA:02', '00-00-00-00-00-03':'E6:D1:8E:C7:3A:A2', '00-00-00-00-00-06':'20:4E:7F:8E:6D:C8', '00-00-00-00-00-07':'84:1B:5E:7A:8D:DB'}

ServerSwitchDpid = '00-00-00-00-00-01'
ServerPort = 4 
ServerIP = '192.168.1.110'
ServerMac = '08:57:00:d7:49:e3'

ManagerIP = '10.0.0.110'
InfoPort = 40012 #send path_map and client_switch to manager
ManagerPort = 40008        #the port that receives message from manager

clientIP_mac = {}
#------end by chen


def _calc_paths ():
  """
  Essentially Floyd-Warshall algorithm
  """

  def dump ():
    for i in sws:
      for j in sws:
        a = path_map[i][j][0]
        #a = adjacency[i][j]
        if a is None: a = "*"
        print a,
      print

  sws = switches.values()
  path_map.clear()
  for k in sws:
    for j,port in adjacency[k].iteritems():
      if port is None: continue
      path_map[k][j] = (1,None)
    path_map[k][k] = (0,None) # distance, intermediate

  #dump()

  for k in sws:
    for i in sws:
      for j in sws:
        if path_map[i][k][0] is not None:
          if path_map[k][j][0] is not None:
            # i -> k -> j exists
            ikj_dist = path_map[i][k][0]+path_map[k][j][0]
            if path_map[i][j][0] is None or ikj_dist < path_map[i][j][0]:
              # i -> k -> j is better than existing
              path_map[i][j] = (ikj_dist, k)

  #print "--------------------"
  #dump()


def _get_raw_path (src, dst):
  """
  Get a raw path (just a list of nodes to traverse)
  """
  if len(path_map) == 0: _calc_paths()
  if src is dst:
    # We're here!
    return []
  if path_map[src][dst][0] is None:
    return None
  intermediate = path_map[src][dst][1]
  if intermediate is None:
    # Directly connected
    return []
  return _get_raw_path(src, intermediate) + [intermediate] + \
         _get_raw_path(intermediate, dst)


def _check_path (p):
  """
  Make sure that a path is actually a string of nodes with connected ports

  returns True if path is valid
  """
  for a,b in zip(p[:-1],p[1:]):
    if adjacency[a[0]][b[0]] != a[2]:
      return False
    if adjacency[b[0]][a[0]] != b[1]:
      return False
  return True


def _get_path (src, dst, first_port, final_port):
  """
  Gets a cooked path -- a list of (node,in_port,out_port)
  """
  # Start with a raw path...
  if src == dst:
    path = [src]
  else:
    path = _get_raw_path(src, dst)
    if path is None: return None
    path = [src] + path + [dst]

  # Now add the ports
  r = []
  in_port = first_port
  for s1,s2 in zip(path[:-1],path[1:]):
    out_port = adjacency[s1][s2]
    r.append((s1,in_port,out_port))
    in_port = adjacency[s2][s1]
  r.append((dst,in_port,final_port))

  assert _check_path(r), "Illegal path!"

  return r


class WaitingPath (object):
  """
  A path which is waiting for its path to be established
  """
  def __init__ (self, path, packet):
    """
    xids is a sequence of (dpid,xid)
    first_switch is the DPID where the packet came from
    packet is something that can be sent in a packet_out
    """
    self.expires_at = time.time() + PATH_SETUP_TIME
    self.path = path
    self.first_switch = path[0][0].dpid
    self.xids = set()
    self.packet = packet

    if len(waiting_paths) > 1000:
      WaitingPath.expire_waiting_paths()

  def add_xid (self, dpid, xid):
    self.xids.add((dpid,xid))
    waiting_paths[(dpid,xid)] = self

  @property
  def is_expired (self):
    return time.time() >= self.expires_at

  def notify (self, event):
    """
    Called when a barrier has been received
    """
    self.xids.discard((event.dpid,event.xid))
    if len(self.xids) == 0:
      # Done!
      if self.packet:
        log.debug("Sending delayed packet out %s"
                  % (dpid_to_str(self.first_switch),))
        msg = of.ofp_packet_out(data=self.packet,
            action=of.ofp_action_output(port=of.OFPP_TABLE))
        core.openflow.sendToDPID(self.first_switch, msg)

      core.l2_multi.raiseEvent(PathInstalled(self.path))


  @staticmethod
  def expire_waiting_paths ():
    packets = set(waiting_paths.values())
    killed = 0
    for p in packets:
      if p.is_expired:
        killed += 1
        for entry in p.xids:
          waiting_paths.pop(entry, None)
    if killed:
      log.error("%i paths failed to install" % (killed,))


class PathInstalled (Event):
  """
  Fired when a path is installed
  """
  def __init__ (self, path):
    self.path = path


class Switch (EventMixin):
  def __init__ (self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None

  def __repr__ (self):
    return dpid_to_str(self.dpid)

  def _install (self, switch, in_port, out_port, match, buf = None):
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.match.in_port = in_port
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.actions.append(of.ofp_action_output(port = out_port))
    msg.buffer_id = buf
    switch.connection.send(msg)

  def _install_path (self, p, match, packet_in=None):
    wp = WaitingPath(p, packet_in)
    for sw,in_port,out_port in p:
      self._install(sw, in_port, out_port, match)
      msg = of.ofp_barrier_request()
      sw.connection.send(msg)
      wp.add_xid(sw.dpid,msg.xid)

  def install_path (self, dst_sw, last_port, match, event):
    """
    Attempts to install a path between this switch and some destination
    """
    p = _get_path(self, dst_sw, event.port, last_port)
    if p is None:
      log.warning("Can't get from %s to %s", match.dl_src, match.dl_dst)

      #import pox.lib.packet as pkt

      if (match.dl_type == pkt.ethernet.IP_TYPE and
          event.parsed.find('ipv4')):
        # It's IP -- let's send a destination unreachable
        log.debug("Dest unreachable (%s -> %s)",
                  match.dl_src, match.dl_dst)

       # from pox.lib.addresses import EthAddr
        e = pkt.ethernet()
        e.src = EthAddr(dpid_to_str(self.dpid)) #FIXME: Hmm...
        e.dst = match.dl_src
        e.type = e.IP_TYPE
        ipp = pkt.ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = match.nw_dst #FIXME: Ridiculous
        ipp.dstip = match.nw_src
        icmp = pkt.icmp()
        icmp.type = pkt.ICMP.TYPE_DEST_UNREACH
        icmp.code = pkt.ICMP.CODE_UNREACH_HOST
        orig_ip = event.parsed.find('ipv4')

        d = orig_ip.pack()
        d = d[:orig_ip.hl * 4 + 8]
        import struct
        d = struct.pack("!HH", 0,0) + d #FIXME: MTU
        icmp.payload = d
        ipp.payload = icmp
        e.payload = ipp
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = event.port))
        msg.data = e.pack()
        self.connection.send(msg)

      return

    log.debug("Installing path for %s -> %s %04x (%i hops)",
        match.dl_src, match.dl_dst, match.dl_type, len(p))

    # We have a path -- install it
    self._install_path(p, match, event.ofp)

    # Now reverse it and install it backwards
    # (we'll just assume that will work)
    p = [(sw,out_port,in_port) for sw,in_port,out_port in p]
    self._install_path(p, match.flip())


  def _handle_PacketIn (self, event):
    def flood ():
      """ Floods the packet """
      if self.is_holding_down:
        log.debug("Not flooding -- holddown active")
      msg = of.ofp_packet_out()
      # OFPP_FLOOD is optional; some switches may need OFPP_ALL
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop ():
      # Kill the buffer
      if event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        event.ofp.buffer_id = None # Mark is dead
        msg.in_port = event.port
        self.connection.send(msg)

    packet = event.parsed

    loc = (self, event.port) # Place we saw this ethaddr
    oldloc = mac_map.get(packet.src) # Place we last saw this ethaddr

    if packet.effective_ethertype == packet.LLDP_TYPE:
      drop()
      return

    if oldloc is None:
      if packet.src.is_multicast == False:
        mac_map[packet.src] = loc # Learn position for ethaddr
        log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
    elif oldloc != loc:
      # ethaddr seen at different place!
      if core.openflow_discovery.is_edge_port(loc[0].dpid, loc[1]):
        # New place is another "plain" port (probably)
        log.debug("%s moved from %s.%i to %s.%i?", packet.src,
                  dpid_to_str(oldloc[0].dpid), oldloc[1],
                  dpid_to_str(   loc[0].dpid),    loc[1])
        if packet.src.is_multicast == False:
          mac_map[packet.src] = loc # Learn position for ethaddr
          log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
      elif packet.dst.is_multicast == False:
        # New place is a switch-to-switch port!
        # Hopefully, this is a packet we're flooding because we didn't
        # know the destination, and not because it's somehow not on a
        # path that we expect it to be on.
        # If spanning_tree is running, we might check that this port is
        # on the spanning tree (it should be).
        if packet.dst in mac_map:
          # Unfortunately, we know the destination.  It's possible that
          # we learned it while it was in flight, but it's also possible
          # that something has gone wrong.
          log.warning("Packet from %s to known destination %s arrived "
                      "at %s.%i without flow", packet.src, packet.dst,
                      dpid_to_str(self.dpid), event.port)

#------by chen
#the client must send a request which is an ip packet
    if packet.type == pkt.ethernet.IP_TYPE:
      if packet.payload.srcip not in clientIP_mac.keys():
        clientIP_mac[packet.payload.srcip] = packet.src
        clientip = str(packet.payload.srcip)
        clientswitch = dpid_to_str(self.dpid)
        send_to_manager('client|'+clientip+':'+clientswitch)
#------end by chen

    if packet.dst.is_multicast:
      log.debug("Flood multicast from %s", packet.src)
      flood()
    else:
      if packet.dst not in mac_map:
        log.debug("%s unknown -- flooding" % (packet.dst,))
        flood()
      else:
        dest = mac_map[packet.dst]
        match = of.ofp_match.from_packet(packet)
        self.install_path(dest[0], dest[1], match, event)

  def disconnect (self):
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None

  def connect (self, connection):
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    log.debug("Connect %s" % (connection,))
    self.connection = connection
    self._listeners = self.listenTo(connection)
    self._connected_at = time.time()

  @property
  def is_holding_down (self):
    if self._connected_at is None: return True
    if time.time() - self._connected_at > FLOOD_HOLDDOWN:
      return False
    return True

  def _handle_ConnectionDown (self, event):
    self.disconnect()


#------by chen
class RtpFromServer(Event):
  """
  Fired when manager inform the controller to build a rtp path from server
  to the client
  """
  def __init__(self, clientIP, dumpPort):
    self.clientIP = clientIP
    self.dumpPort = dumpPort
	
class RtpFromSwitch(Event):
  """
  Fired when manager inform the controller to build a rtp path from a 
  switch to the client
  """
  def __init__(self, switchDpid, clientIP, dumpPort):
    self.switchDpid = switchDpid
    self.clientIP = clientIP
    self.dumpPort = dumpPort

#------end by chen

class l2_multi (EventMixin):

  _eventMixin_events = set([
    PathInstalled, RtpFromServer,RtpFromSwitch
  ])

  def __init__ (self):
    # Listen to dependencies (specifying priority 0 for openflow)
    core.listen_to_dependencies(self, listen_args={'openflow':{'priority':0}})

  def _handle_openflow_discovery_LinkEvent (self, event):
    def flip (link):
      return Discovery.Link(link[2],link[3], link[0],link[1])

    l = event.link
    sw1 = switches[l.dpid1]
    sw2 = switches[l.dpid2]

    # Invalidate all flows and path info.
    # For link adds, this makes sure that if a new link leads to an
    # improved path, we use it.
    # For link removals, this makes sure that we don't use a
    # path that may have been broken.
    #NOTE: This could be radically improved! (e.g., not *ALL* paths break)
    clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    for sw in switches.itervalues():
      if sw.connection is None: continue
      sw.connection.send(clear)
    path_map.clear()

    if event.removed:
      # This link no longer okay
      if sw2 in adjacency[sw1]: del adjacency[sw1][sw2]
      if sw1 in adjacency[sw2]: del adjacency[sw2][sw1]

      # But maybe there's another way to connect these...
      for ll in core.openflow_discovery.adjacency:
        if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:
          if flip(ll) in core.openflow_discovery.adjacency:
            # Yup, link goes both ways
            adjacency[sw1][sw2] = ll.port1
            adjacency[sw2][sw1] = ll.port2
            # Fixed -- new link chosen to connect these
            break
    else:
      # If we already consider these nodes connected, we can
      # ignore this link up.
      # Otherwise, we might be interested...
      if adjacency[sw1][sw2] is None:
        # These previously weren't connected.  If the link
        # exists in both directions, we consider them connected now.
        if flip(l) in core.openflow_discovery.adjacency:
          # Yup, link goes both ways -- connected!
          adjacency[sw1][sw2] = l.port1
          adjacency[sw2][sw1] = l.port2

      # If we have learned a MAC on this port which we now know to
      # be connected to a switch, unlearn it.
      bad_macs = set()
      for mac,(sw,port) in mac_map.iteritems():
        if sw is sw1 and port == l.port1: bad_macs.add(mac)
        if sw is sw2 and port == l.port2: bad_macs.add(mac)
      for mac in bad_macs:
        log.debug("Unlearned %s", mac)
        del mac_map[mac]

  def _handle_openflow_ConnectionUp (self, event):
    sw = switches.get(event.dpid)
    if sw is None:
      # New switch
      sw = Switch()
      switches[event.dpid] = sw
      sw.connect(event.connection)
    else:
      sw.connect(event.connection)

#------by chen
    switchMac = EthAddr(DPID_MAC[dpid_to_str(event.dpid)])

    match1 = of.ofp_match()
    match1.dl_type = pkt.ethernet.ARP_TYPE
    match1.dl_src = switchMac
    match1.in_port = of.OFPP_LOCAL
    flow1 = of.ofp_flow_mod()
    flow1.match = match1
    flow1.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
    event.connection.send(flow1)

    match2 = of.ofp_match()
    match2.dl_type = pkt.ethernet.ARP_TYPE
    match2.dl_dst = switchMac
    flow2 = of.ofp_flow_mod()
    flow2.match = match2
    flow2.actions.append(of.ofp_action_output(port = of.OFPP_LOCAL))
    event.connection.send(flow2)
#------end by chen

  def _handle_openflow_BarrierIn (self, event):
    wp = waiting_paths.pop((event.dpid,event.xid), None)
    if not wp:
      #log.info("No waiting packet %s,%s", event.dpid, event.xid)
      return
    #log.debug("Notify waiting packet %s,%s", event.dpid, event.xid)
    wp.notify(event)

#------by chen
def _install_rtp(switch, in_port, out_port, match, dumpPort):

  msg = of.ofp_flow_mod()
  msg.match = match
  msg.match.in_port = in_port

  msg.actions.append(of.ofp_action_output(port = out_port))
  if in_port != of.OFPP_LOCAL: 
    msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr('192.168.1.1')))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(DPID_MAC[dpid_to_str(switch.dpid)])))
    msg.actions.append(of.ofp_action_tp_port.set_dst(dumpPort))
    msg.actions.append(of.ofp_action_output(port = of.OFPP_LOCAL))

  switch.connection.send(msg)

def _install_rtp_path(p, match, dumpPort):
  for sw,in_port,out_port in p:
    _install_rtp(sw, in_port, out_port, match, dumpPort)

class RtpHandle:
  def __init__(self):
    core.l2_multi.addListeners(self)

  def _handle_RtpFromServer(self, event):
		
    clientMac = clientIP_mac[event.clientIP]
    dest = mac_map[clientMac]
    serverswitch = switches[str_to_dpid(ServerSwitchDpid)]
    p =_get_path(serverswitch, dest[0], ServerPort, dest[1])

    match = of.ofp_match()
    match.dl_type = pkt.ethernet.IP_TYPE
    match.dl_src = EthAddr(ServerMac)
    match.dl_dst = clientMac
    match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    match.nw_src = IPAddr(ServerIP)
    match.nw_dst = event.clientIP

    _install_rtp_path(p, match, event.dumpPort)

  def _handle_RtpFromSwitch(self, event):
    
    clientMac = clientIP_mac[event.clientIP]
    dest = mac_map[clientMac]
    switch = switches[event.switchDpid]
    switchMac = EthAddr(DPID_MAC[dpid_to_str(switch.dpid)])
    p = _get_path(switch, dest[0], of.OFPP_LOCAL, dest[1])

    match = of.ofp_match()
    match.dl_type = pkt.ethernet.IP_TYPE
    match.dl_src = switchMac
    match.dl_dst = clientMac
    #match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    match.nw_src = IPAddr('192.168.1.1')
    match.nw_dst = event.clientIP


    match1 = of.ofp_match()
    match1.dl_type = pkt.ethernet.IP_TYPE
    match1.dl_dst = switchMac
    match1.dl_src = clientMac
    match1.in_port = dest[1]
    flow1 = of.ofp_flow_mod()
    flow1.match = match1
    flow1.actions.append(of.ofp_action_output(port = of.OFPP_LOCAL))
    switch.connection.send(flow1)

    match2 = of.ofp_match()
    match2.dl_type = pkt.ethernet.ARP_TYPE
    match2.dl_src = switchMac
    match2.in_port = of.OFPP_LOCAL
    flow2 = of.ofp_flow_mod()
    flow2.match = match2
    flow2.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
    switch.connection.send(flow2)

    match3 = of.ofp_match()
    match3.dl_type = pkt.ethernet.ARP_TYPE
    match3.dl_dst = switchMac
    flow3 = of.ofp_flow_mod()
    flow3.match = match3
    flow3.actions.append(of.ofp_action_output(port = of.OFPP_LOCAL))
    switch.connection.send(flow3)

    _install_rtp_path(p, match, event.dumpPort)

def send_to_manager(message):
  s = socket(AF_INET, SOCK_STREAM)
  s.connect((ManagerIP, InfoPort))
  s.send(message)
  s.close()

def pathmapToStr():
  paths = []
  _calc_paths()
  for k1 in path_map.keys():
    for k2 in path_map[k1].keys():
      path = []
      path.append(str(k1))
      path.append(str(k2))
      path.append(str(path_map[k1][k2][0]))
      path.append(str(path_map[k1][k2][1]))
      paths.append(':'.join(path))
  return '->'.join(paths)

def send_path_map():  #thread
  while True:
    send_to_manager('pathmap|' + pathmapToStr())
    time.sleep(30)

def recv_manager_command():    #thread
  s = socket(AF_INET, SOCK_STREAM)
  s.bind(('', ManagerPort))
  s.listen(5)
  while True:	
    conn, addr = s.accept()
    message = conn.recv(1024)
    command = message.split('->')
    if command[0] == 'server':
      core.l2_multi.raiseEvent(RtpFromServer, IPAddr(command[1]), int(command[2]))
    elif command[0] == 'switch':
      core.l2_multi.raiseEvent(RtpFromSwitch, str_to_dpid(command[1]), IPAddr(command[2]), int(command[3]))
    elif command[0] == 'init':
      threading.Thread(target = send_path_map, args = ()).start()

#------end by chen

def launch ():
  core.registerNew(l2_multi)
#------by chen
  core.registerNew(RtpHandle)

  thread1 = threading.Thread(target = recv_manager_command, args = ())
  thread1.start()
#------end by chen
  timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)
