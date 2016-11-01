from socket import socket, AF_INET, SOCK_STREAM
import threading
import time
import os
from collections import defaultdict

path_map = defaultdict(lambda:defaultdict(lambda:(None,None)))
clientIP_dpid = defaultdict(lambda:None)

#video->[Window, ]
establishWindows = defaultdict(lambda:[])

ControllerIP = '10.0.0.99'
ControllerPort = 40008     #the listen port of the controllerIn
InfoPort = 40012 #the port controller send path_map and client info to

ClientPort = 40004    #the port that receives requests of clients

SW_PORT = 5561

DPID_IP = {'00-00-00-00-00-01':'10.0.0.1', '00-00-00-00-00-02':'10.0.0.2', '00-00-00-00-00-03':'10.0.0.3', '00-00-00-00-00-06':'10.0.0.6', '00-00-00-00-00-07':'10.0.0.7'}

server_dpid = '00-00-00-00-00-01'

InitialLength = 180 #seconds
MaxLength = 300 #seconds
MaxClients = 10
InitialInterval = 99
Video_Length = {'1.ts':10}#video->length(minutes)

DumpPort = 10000

def send_to_switch(switch_ip, command): #eg. 'rtpdump->1->01.dump->5004'
  s = socket(AF_INET, SOCK_STREAM) # 'rtpplay->01.dump->192.168.1.99->5004'
  s.connect((switch_ip, SW_PORT))
  s.send(command)
  s.close()

def send_to_controller(command):   #eg. 'server->192.168.1.99->5004'
  s = socket(AF_INET, SOCK_STREAM) # 'switch->00-00-00-00-00-02->ip->5004'
  s.connect((ControllerIP, ControllerPort))
  s.send(command)
  s.close()

def recv_request():   #thread
  s = socket(AF_INET, SOCK_STREAM)
  s.bind(('', ClientPort))
  s.listen(100)	

  while True:
    conn, addr = s.accept()
#should be changed
    request = conn.recv(1024)
    info = request.split('->')
    video = info[0]
    playPort = info[1]
    thread = threading.Thread(target = handle_request, args = (str(addr[0]),video, playPort)).start()
#-----

#---core part
class Window:
  def __init__(self, video, dpid, dumpPort):
    self.video = video
    self.dpid = dpid
    self.dumpPort = dumpPort
    self.initialTime = int(time.time())
    self.clients = [] #[(clientIP, startTime),]
    self.dumpName = video + '_' + str(self.initialTime) + '.dump'
    establishWindows[video].append(self)

#may change when adding new clients
    self.length = InitialLength
    self.interval = InitialInterval
    self.waiting_time = InitialLength
    self.last_client_time = None

    self.dump_video() #send dump command


  @property
  def establishing(self):
    return ((int(time.time()) - self.initialTime) < self.length) & (len(self.clients) < MaxClients)

  def update(self):
    self.waiting_time = self.initialTime + self.length - self.last_client_time

  def add_client(self, clientIP, playPort):
    startTime = int(time.time())
    self.last_client_time = startTime
    self.clients.append((clientIP, startTime))
    command = 'rtpplay->%s->%s->%s' % (self.dumpName, clientIP, playPort)
    send_to_switch(DPID_IP[self.dpid], command)
    
    self.update()#adopt the algrithm to determine the duration of the moving window

  def dump_video(self):
    dumplength = Video_Length[self.video]
    command = 'rtpdump->%s->%s->%s' % (dumplength, self.dumpName, self.dumpPort)
    send_to_switch(DPID_IP[self.dpid], command)


def get_serve_node(clientIP, video):

  legalWindows = []
  for window in establishWindows[video]:
    if window.establishing:
      legalWindows.append(window)

  if legalWindows == []:
    return 'server'

  client_dpid = clientIP_dpid[clientIP]
  best_window = None
  serve_node = 'server'
  min_dis = path_map[server_dpid][client_dpid][0] + 1
  for window in legalWindows:
    dis = path_map[window.dpid][client_dpid][0]
    if dis <= min_dis:
      best_window = window
      serve_node = window.dpid
      min_dis = dis

  establishWindows[video] = legalWindows #update establishWindows
  if best_window == None:
    return serve_node
  else:
    return (serve_node, best_window)

def get_port(): #return str(int) to represent the chosen dumpPort which is unused
  global DumpPort
  DumpPort += 2
  if DumpPort > 20000:
    DumpPort = 10000
  return str(DumpPort)

def _get_raw_path(src, dst):
  intermediate = path_map[src][dst][1]
  if (intermediate == 'None') | (intermediate is None):
    return []
  return _get_raw_path(src, intermediate) + [intermediate] + _get_raw_path(intermediate, dst)

def get_path(src_dpid, dst_dpid):#return a list of Switch
  if src_dpid == dst_dpid:
    return [src_dpid]
  return [src_dpid] + _get_raw_path(src_dpid, dst_dpid) + [dst_dpid]

def send_rtp_from_server(clientIP, video, playPort):
  dumpPort = get_port()
  command = 'server->%s->%s' % (clientIP, dumpPort)
  send_to_controller(command)
  time.sleep(1) #make sure flow rules are installed 
  path = get_path(server_dpid, clientIP_dpid[clientIP])
  for dpid in path:
    Window(video, dpid ,dumpPort)
  os.system("vlc ~/server/media/%s --sout='#rtp{dst=%s,port=%s,mux=ts}'" % (video, clientIP, playPort))

def send_rtp_from_switch(serve_node, clientIP, video, playPort):
  dumpPort = get_port()
  src_dpid = serve_node[0]
  window = serve_node[1]
  path = get_path(src_dpid, clientIP_dpid[clientIP])
  window.add_client(clientIP, playPort)
  for dpid in path[1:]:
    Window(video, dpid, dumpPort)

def handle_request(clientIP, video, playPort):
  serve_node = get_serve_node(clientIP, video)
  if serve_node == 'server':
    send_rtp_from_server(clientIP, video, playPort)
    print 'send rtp from server' #test
  else:
    send_rtp_from_switch(serve_node, clientIP, video, playPort)
    print 'send rtp from switch' #test
#---

def test_dump(clientIP, video):
  send_to_controller('server->%s->15004' % clientIP)
  print 'send to controller: server->%s' % clientIP #test
  time.sleep(2) #make sure the path is installed
  send_to_switch('10.0.0.1', 'rtpdump->1->build.dump->15004')
  send_to_switch('10.0.0.2', 'rtpdump->1->build.dump->15004')
  os.system("vlc ~/server/media/%s --sout='#rtp{dst=%s,mux=ts}'" % (video, str(clientIP)))
  print "run: vlc %s --sout='#rtp{dst=%s,mux=ts}'" % (video, clientIP) #test

def test_play(clientIP):
  send_to_controller('switch->00-00-00-00-00-01->%s->15006' % clientIP)
  time.sleep(2)
  send_to_switch('10.0.0.1', 'rtpplay->build.dump->%s->5004' % clientIP)
  send_to_switch('10.0.0.2', 'rtpdump->1->play.dump->15006')

def strToPathmap(msg):
  paths = msg.split('->')
  for k in paths:
    path = k.split(':')
    path_map[path[0]][path[1]] = (int(path[2]), path[3])

def recv_info(): #thread
  s = socket(AF_INET, SOCK_STREAM)
  s.bind(('', InfoPort))
  s.listen(5)
  while True:
    conn, addr = s.accept()
    message = conn.recv(2048)
    print message #test
    command = message.split('|')
    if command[0] == 'pathmap':
      strToPathmap(command[1])
    elif command[0] == 'client':
      clientloc = command[1].split(':')
      clientIP_dpid[clientloc[0]] = clientloc[1] 

def test():
  thread1 = threading.Thread(target = recv_request,args = ())
  thread1.start()

  thread2 = threading.Thread(target = recv_info,args = ())
  thread2.start()

  time.sleep(30)
  send_to_controller('init')
	
if __name__ == '__main__':
  test()
