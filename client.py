import os
from socket import socket, AF_INET, SOCK_STREAM

ServerPort = 40004   #the listen port of the server
ServerIP = '192.168.1.110'

def send_request(video):  #eg. '1'
  s = socket(AF_INET, SOCK_STREAM)
  s.connect((ServerIP, ServerPort))
  s.send(video)
  s.close()

def play_video(port = 5004):
  os.system('vlc rtp://@:%d' % port)

def test():
  #send_request('~/Videos/conan.ts') #should be changed
  send_request('1.ts')
  play_video()

if __name__ == '__main__':
  test()
