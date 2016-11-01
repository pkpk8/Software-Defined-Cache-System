#!/usr/bin/env python2
#-*-encoding:utf-8-*-
import os,sys,socket
import thread
import threading
import time
import psutil
import re

manageip = '127.0.0.1'  #需要设置管理服务器ip
dir = '/home/zlk/Server/media'
VLC ="vlc -vvv /home/zlk/Server/media/Nian-720P.ts --sout='#duplicate{dst=rtp{dst=%s,port=5004,mux=ts,ttl=1},dst=display}'"

def send_videolist():
  
	list = os.listdir(dir)  #列出目录下的所有文件和目录	
	s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	port = 40000
	s1.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	s1.connect((manageip,port)) #连接管理服务器ip
	s1.send(str(list))  #list是一个列表，不能被send，要转换为str或buf才行
        print 'list send'
	s1.close()
#dir = '/home/zlk/Server/media'
#send_videolist(dir)


                             



def recv_con():    #接收控制器指令

        def processinfo(x):
                    p = psutil.get_process_list()
                    for r in p:
                        aa = str(r)
                        f = re.compile(x,re.I)
                        if f.search(aa):
                             bb=aa.split('pid=')
                             cc=bb[1]
                             dd=cc.split(', name')
                             pid=dd[0]
                             continue
                    return pid

	def send_num(managerip,num):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		port = 40016
		s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)  
		s.connect((managerip,port))  #连接客户端ip
		s.send(num)  
		s.close()

        def vlc1():               
                os.system("vlc -vvv /home/zlk/Server/media/Nian-720P.ts --sout='#duplicate{dst=rtp{dst=%s,port=8080,mux=ts,ttl=1},dst=display}'" %client) 
                               
               
        def vlc2():             
                os.system("vlc -vvv /home/zlk/Server/media/WildChina.ts --sout='#duplicate{dst=rtp{dst=%s,port=5004,mux=ts,ttl=1},dst=display}'" %client)
             
	s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	port = 5560
	s1.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1) 
        s1.bind((s1.getsockname()[0],port))  #绑定管理服务器本身的ip
        s1.listen(100) 
        while True:
		connection,address=s1.accept()
		info = connection.recv(1024)
                inf = info.split('#')
                video = inf[0]
                client = inf[1] 
                print video
                if(video == 'Nian'):
                     thread.start_new_thread(vlc1,())
                     time.sleep(1)
                     pidvlc1 = processinfo("vlc")
                     send_num('127.0.0.1',video+'#'+pidvlc1)
		     #os.system("vlc -vvv /home/zlk/Server/media/Nian-720P.ts --sout='#duplicate{dst=rtp{dst=%s,port=5004,mux=ts,ttl=1},dst=display}'" %client) 
                  #os.system("vlc -vvv /home/zlk/Server/media/Nian-720P.ts --sout='#duplicate{dst=rtp{sdp=rtsp://:8080/test},dst=display}'")  
	        elif(video == 'WildChina'):
                     thread.start_new_thread(vlc2,())
                     time.sleep(1)
                     pidvlc1 = processinfo("vlc")
                     send_num('127.0.0.1',video+'#'+pidvlc1)

                  #os.system("vlc -vvv /home/zlk/Server/media/WildChina.ts --sout='#duplicate{dst=rtp{sdp=rtsp://:8080/test},dst=display}'")
                else:
                  print "Video error"  
    
        s1.close()
 


def test():

    thread.start_new_thread(send_videolist,())
    thread.start_new_thread(recv_con,())


    time.sleep(1000)

if __name__=='__main__':
    test()
   
