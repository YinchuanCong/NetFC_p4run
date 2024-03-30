import nnpy
import struct
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import Ether, sniff, Packet, BitField, raw
import numpy as np 


class L2Controller(object):

    def __init__(self, sw_name):
        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)


    def unpack_digest(self, msg, num_samples):
        digest = []
        starting_index = 32
        # num_samples = 1
        # print(num_samples)
        
        for sample in range(num_samples):
            # print(len(msg))
            # print(msg[starting_index:starting_index+2])
            # print(bin(struct.unpack(">H",msg[starting_index:starting_index+2])[0]))
            (x,y,z) = struct.unpack(">eee", msg[starting_index:starting_index+6])# 2 for 2 bytes
            # print(msg[starting_index:starting_index+2])
            # score = msg[starting_index:starting_index+12]
            
            
            # src_addr = '%i.%i.%i.%i'%(src>>24,(src>>16)&0x000f, (src>>8)&0x000f,src&0x000f)
            # dst_addr = '%i.%i.%i.%i'%(dst>>24,(dst>>16)&0x000f, (dst>>8)&0x000f,dst&0x000f)
            
            print('x:',np.float32(x),end=' ')
            print(''.join(format(by,'08b') for by in struct.pack('!e',x)))
            print('y:',np.float32(y),end=' ')
            print(''.join(format(by,'08b') for by in struct.pack('!e',y)))
            print('z:',np.float32(z),end=' ')
            print(''.join(format(by,'08b') for by in struct.pack('!e',z)))
            # print('time :',time)
            print()
            starting_index +=6
            
            # digest.append(tmp)
        return digest

    def recv_msg_digest(self, msg):
        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
                                                                          msg[:32])
        print(num)
        digest = self.unpack_digest(msg, num)
        # self.learn(digest)
        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

    def run_digest_loop(self):
        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        notifications_socket = self.controller.client.bm_mgmt_get_info().notifications_socket
        sub.connect(notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')
        print('starting digesr:')
        
        while True:
            msg = sub.recv()
            self.recv_msg_digest(msg)



if __name__ == "__main__":
    sw_name = 's1'
    receive_from = "digest"
    if receive_from == "digest":
        controller = L2Controller(sw_name).run_digest_loop()