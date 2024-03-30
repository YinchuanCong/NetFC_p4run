import nnpy
import struct
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import Ether, sniff, Packet, BitField, raw
import random 
# import cPickle as pkl 
import pickle as pkl
import os 
# import numpy as np
import math 

SCALING_FACTOR = 256


def float_to_binary(float_value):
    # 将浮点数打包为字节数据
    bytes_data = struct.pack('!e', float_value)
    
    # 将字节数据转换为16位二进制字符串
    binary_str = ''.join(format(byte, '08b') for byte in bytes_data)
    
    return binary_str[:16]


def int_to_binary(float_value):
    # 将浮点数打包为字节数据
    bytes_data = struct.pack('!h', float_value)
    
    # 将字节数据转换为16位二进制字符串
    binary_str = ''.join(format(byte, '08b') for byte in bytes_data)
    
    return binary_str[:16]



class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr',0,48), BitField('ingress_port', 0, 16)]


class L2Controller(object):
    def __init__(self,sw_name):
        self.topo= load_topo('topology.json')
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(self.sw_name)
        self.cpu_port = self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)
        self.init()
        
    def init(self):
        pass 
        self.controller.reset_state()
        
        
    def run_test(self):
        
        
        self.controller.table_add('dmac','forward',['10.0.0.1/32'],['1'])
        self.controller.table_add('dmac','forward',['10.0.0.2/32'],['2'])
        self.controller.table_add('dmac','forward',['11.1.0.0/16'],['1'])
        self.controller.table_add('dmac','forward',['11.2.0.0/16'],['2'])
        
        
        
        '''
        action get_info_action(bit<8> info) {
            ig_md.ac_md.info = info;
        }

        table get_info_table {
            key = {
                hdr.calc.x[15:15] : exact;
                hdr.calc.y[15:15] : exact;
                ig_md.ac_md.sign[15:15] : exact;
            }
            actions = {
                get_info_action;
            }
            size = 8;
        }

        '''
        # self.controller.table_add('get_info_table','get_info_action',['0','0','0'],['0'])
        # self.controller.table_add('get_info_table','get_info_action',['0','0','1'],['1'])
        # self.controller.table_add('get_info_table','get_info_action',['0','1','0'],['2'])
        # self.controller.table_add('get_info_table','get_info_action',['0','1','1'],['3'])
        # self.controller.table_add('get_info_table','get_info_action',['1','0','0'],['4'])
        # self.controller.table_add('get_info_table','get_info_action',['1','0','1'],['5'])
        # self.controller.table_add('get_info_table','get_info_action',['1','1','0'],['6'])
        # self.controller.table_add('get_info_table','get_info_action',['1','1','1'],['7'])
        # self.controller.table_add('get_info_table','get_info_action',['0'],['0'])
        # self.controller.table_add('get_info_table','get_info_action',['1'],['1'])
        # self.controller.table_add('get_info_table','get_info_action',['2'],['2'])
        # self.controller.table_add('get_info_table','get_info_action',['3'],['3'])
        # self.controller.table_add('get_info_table','get_info_action',['4'],['4'])
        # self.controller.table_add('get_info_table','get_info_action',['5'],['5'])
        # self.controller.table_add('get_info_table','get_info_action',['6'],['6'])
        # self.controller.table_add('get_info_table','get_info_action',['7'],['7'])
        
        
        '''
        action get_log_i_action(int<16> log_i) {
            ig_md.ac_md.log_i = log_i;
        }

        table get_log_i_table {
            key = {
                ig_md.ac_md.frac_x : exact;
            }

            actions = {
                get_log_i_action;
            }

            size = 32768; 
        }
        ''' 
        # for i in range(1,2**15):
        #     ## 无穷大，不考虑
        #     if i&0b0111110000000000 == 0b0111110000000000:
        #         continue
        #     print(i,end=' ')
        #     binary = format(i,'016b')
        #     print(binary)
        #     bytes_data = int(binary,2).to_bytes(2,byteorder='big')
        #     float_value = struct.unpack('!e', bytes_data)[0]
        #     print(float_value)
            
        #     log_i = int(math.log2(float_value)*SCALING_FACTOR)
        #     print(log_i,end=' ')
            
            
        #     log_i_str = ''.join(format(by,'08b') for by in struct.pack('>h',log_i))
        #     print(log_i_str)
        #     print()
        #     self.controller.table_add('get_log_i_table','get_log_i_action',['0b'+binary],['0b'+log_i_str])
        for i in range(1,2**16):
            try:
                ## 无穷大，不考虑
                if i&0b0111110000000000 == 0b0111110000000000:
                    continue
                print(i,end=' ')
                binary = format(i,'016b')
                print(binary)
                bytes_data = int(binary,2).to_bytes(2,byteorder='big')
                float_value = struct.unpack('!e', bytes_data)[0]
                print(float_value)
                
                log_i = int(math.log2(float_value)*SCALING_FACTOR)
                print(log_i,end=' ')
                
                
                log_i_str = ''.join(format(by,'08b') for by in struct.pack('>h',log_i))
                print(log_i_str)
                print()
                self.controller.table_add('get_log_i_table','get_log_i_action',['0b'+binary],['0b'+log_i_str])
            except:
                print('Table: get_log_i_action, error at',i)
        
        
        '''
        action get_log_j_action(int<16> log_j) {
            ig_md.ac_md.log_j = log_j;
        }
        
        table get_log_j_table {
            key = {
                ig_md.ac_md.frac_y : exact;
            }

            actions = {
                get_log_j_action;
            }

            size = 32768; 
        }
        '''
        # for i in range(1,2**15):
        #     ## 无穷大，不考虑
        #     if i&0b0111110000000000 == 0b0111110000000000:
        #         continue
        #     print(i,end=' ')
        #     binary = format(i,'016b')
        #     print(binary)
        #     bytes_data = int(binary,2).to_bytes(2,byteorder='big')
        #     float_value = struct.unpack('!e', bytes_data)[0]
        #     print(float_value)
        #     log_i = int(math.log2(float_value)*SCALING_FACTOR)
        #     print(log_i,end=' ')
        #     log_i_str = ''.join(format(by,'08b') for by in struct.pack('>h',log_i))
        #     print(log_i_str)
        #     print()
        #     self.controller.table_add('get_log_j_table','get_log_j_action',['0b'+binary],['0b'+log_i_str])
        for i in range(1,2**16):
            try:
                ## 无穷大，不考虑
                if i&0b0111110000000000 == 0b0111110000000000:
                    continue
                print(i,end=' ')
                binary = format(i,'016b')
                print(binary)
                bytes_data = int(binary,2).to_bytes(2,byteorder='big')
                float_value = struct.unpack('!e', bytes_data)[0]
                print(float_value)
                log_i = int(math.log2(float_value)*SCALING_FACTOR)
                print(log_i,end=' ')
                log_i_str = ''.join(format(by,'08b') for by in struct.pack('>h',log_i))
                print(log_i_str)
                print()
                self.controller.table_add('get_log_j_table','get_log_j_action',['0b'+binary],['0b'+log_i_str])
            except:
                print('Table: get_log_j_action, error at',i)
    
            
        '''
        action get_abs_z_action(bit<16> abs_z) {
            hdr.calc.z = abs_z;
        }

        table get_abs_z_table {
            key = {
            ig_md.ac_md.n : exact;
            }
            actions = {
                get_abs_z_action;
            }

            size = 65536; 
        }
        '''
        for i in range(int(-100*SCALING_FACTOR),int(100*SCALING_FACTOR)):
            try:
                print(i,end='   ')
                # binary_str = bin(i)[2:].zfill(16)
                binary_str = ''.join(format(by,'08b') for by in struct.pack('!h',i))
                print('binary_str=',binary_str)
                # float_value = struct.unpack('!e', bytes.fromhex(hex(int(binary_str, 2))[2:].zfill(4)))[0]
                # exp_i = math.log2(1-2**float_value)
                # print(float_value)
                exp_i = 2**(i*1.0/SCALING_FACTOR)*1.0
                # exp_i_str=float_to_binary(float_value=exp_i)
                exp_i_str=''.join(format(by,'08b') for by in struct.pack('!e',exp_i))
                print('exp_i=',exp_i,end='   ')
                print('exp_i_str=',exp_i_str)
                print() 
                self.controller.table_add('get_abs_z_table','get_abs_z_action',['0b'+binary_str],['0b'+exp_i_str])
                
                # binary_str= list(binary_str)
                # binary_str[0]= '1'
                # # print(binary_str)
                # binary_str = ''.join(binary_str)
                # print(binary_str)
                # exp_i = 2**(i*(-1.0)/SCALING_FACTOR)*1.0
                # exp_i_str=float_to_binary(float_value=exp_i)
                # print('exp_i=',exp_i,end='   ')
                # print('exp_i_str=',exp_i_str)
                # print() 
                # self.controller.table_add('get_abs_z_table','get_abs_z_action',['0b'+binary_str],['0b'+exp_i_str])
                
            except:
                print('Table: get_abs_z_table, error at',i) 
            
        
        
        # self.get_table_configuration()
        # self.add_entry_to_tables()
        
        
if __name__ == '__main__':
    con = L2Controller('s1')
    con.run_test()
        