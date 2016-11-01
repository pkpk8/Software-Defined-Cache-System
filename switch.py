from socket import socket, AF_INET, SOCK_STREAM
import threading
import os

SW_PORT = 5561

def recv_command(): #thread
  s = socket(AF_INET, SOCK_STREAM)
  s.bind(('', SW_PORT))
  s.listen(5)

  while True:
    conn, addr = s.accept()
    command = conn.recv(1024)
    thread = threading.Thread(target = handle_command, args = (command,))
    thread.start()

def handle_command(msg):
  command = msg.split('->')

  if command[0] == 'rtpdump':
    os.system("/mnt/rtpdump -F dump -t %s -o /mnt/%s /%s" % (command[1], command[2], command[3]))
    print 'finish rtpdump'
  elif command[0] == 'rtpplay':
    os.system("/mnt/rtpplay -f /mnt/%s %s/%s" % (command[1], command[2], command[3]))
    print 'finish rtpplay'


thread = threading.Thread(target = recv_command, args = ())
thread.start()
