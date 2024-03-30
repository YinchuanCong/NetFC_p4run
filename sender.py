from scapy.all  import sendp, get_if_list, get_if_hwaddr
from scapy.all  import Ether, IP, TCP, UDP, Raw ,Packet,ShortField,BitField,IntField
import csv 
import random
import time 
import struct 
import numpy as np 

class TimeStep(Packet):
    name = 'TimeStep'
    fields_desc = [
        ShortField("TimeStep", 0),
        ShortField("protocol",0),
        # IntField('x',0),
        # IntField('y',0)
                   ]

class CalcH(Packet):
    name = 'calculat Header'
    fields_desc = [
        ShortField("x", 0),
        ShortField("y",0),
        ShortField('z',0),
        ShortField("protocol",0)
                   ]
# 注意要把报文头对齐 !!!!
    
    



def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


src =[]
dst =[]
tim=[]
with open('darpa_processed_1.csv') as f:
    c =  csv.reader(f)
    for row in c:
        src.append(int(row[0]))
        dst.append(int(row[1]))
        tim.append(int(row[2]))
        break



for i in range(100000):#100000
    pass 
    IP_src = '%i.%i.%i.%i'%(11,1,src[0]>>8,src[0]&0xf)
    IP_dst = '%i.%i.%i.%i'%(11,2,dst[0]>>8,dst[0]&0xf)
    sport = 5000
    dport = 5001
    
    print(IP_src,IP_dst)
    iface = get_if()
    
    mac_src = '00:00:0a:00:00:01'
    mac_dst = '00:00:0a:00:00:02'
    
    pkt = Ether(src= mac_src, dst = mac_dst)
    
    # pkt = pkt/IP(src=IP_src,dst=IP_dst)/TimeStep(TimeStep=tim[i].to_bytes(2,'big'),protocol=b'\x00\x00')/TCP(dport=random.randint(5000,60000), sport=random.randint(49152,65535))/Raw(tim[i].to_bytes(2,'big'))
    random.seed(i+10240)
    x= random.uniform(-65504/2,65504/2)
    random.seed(i+10241)
    y= random.uniform(-65504/2,65504/2)
    # x=-425.0   
    # y=-50.0
    print("x:",np.float16(x),'y:',np.float16(y))
    ###############################################################################
    x=int.from_bytes(struct.pack('!e', x),byteorder='big', signed=False)
    y=int.from_bytes(struct.pack('!e', y),byteorder='big', signed=False)
    
    print("bin(x):",''.join(format(by, '08b') for by in struct.pack('!H',x)))
    print("bin(y):",''.join(format(by, '08b') for by in struct.pack('!H',y)))
    print()
    ################################################################################
    
    pkt = pkt/IP(src=IP_src,dst=IP_dst,proto=3)/CalcH(x=x,y=y,z=0,protocol=0)/TimeStep(TimeStep=0,protocol=6)/TCP(dport=random.randint(5000,60000), sport=random.randint(49152,65535))/Raw(tim[0].to_bytes(2,'big'))
    # print(pkt)
    
    sendp(pkt, iface = iface, verbose=False) 
    time.sleep(0.1)