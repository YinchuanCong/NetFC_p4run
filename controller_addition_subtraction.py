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
        self.controller.table_add('get_info_table','get_info_action',['0'],['0'])
        self.controller.table_add('get_info_table','get_info_action',['1'],['1'])
        self.controller.table_add('get_info_table','get_info_action',['2'],['2'])
        self.controller.table_add('get_info_table','get_info_action',['3'],['3'])
        self.controller.table_add('get_info_table','get_info_action',['4'],['4'])
        self.controller.table_add('get_info_table','get_info_action',['5'],['5'])
        self.controller.table_add('get_info_table','get_info_action',['6'],['6'])
        self.controller.table_add('get_info_table','get_info_action',['7'],['7'])
        
        
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
        action set_flag_0_action(bit<16> sign_z) {
            ig_md.ac_md.flag = 0;
            ig_md.ac_md.sign_z = sign_z;
        }

        action set_flag_1_action(bit<16> sign_z) {
            ig_md.ac_md.flag = 1;
            ig_md.ac_md.sign_z = sign_z;

        }

        action set_flag_2_action(bit<16> sign_z) {
            ig_md.ac_md.flag = 2;
            ig_md.ac_md.sign_z = sign_z;
        }

        table get_flag_table {
            key = {
            ig_md.ac_md.info : exact;
            }
            actions = {
                set_flag_0_action;
                set_flag_1_action;
                set_flag_2_action;
            }

            size = 8; 
        }
        '''
        info_to_flag_list = [[0,0,0],[1,0,0],[2,1,0],[3,2,32768],[4,1,32768],[5,2,0],[6,0,32768],[7,0,32768]]
        for item in info_to_flag_list:
            self.controller.table_add('get_flag_table','set_flag_%d_action'%item[1],['%d'%item[0]],['%d'%item[2]])
        # 32768 = 0b0100 0000 0000 0000
        
        
        '''
        action get_log_m_0_action(int<16> log_m) {
            ig_md.ac_md.log_m = log_m;
        }

        table get_log_m_0_table {
            key = {
            ig_md.ac_md.log_k : exact;
            }
            actions = {
                get_log_m_0_action;
            }
            size = 65536; 
        }

        '''
        # for i in range(-15,16):
        for i in range(-1024,1024):
            try:
                print(i,end='   ')
                # binary_str = bin(i)[2:].zfill(16)
                binary_str = ''.join(format(by,'08b') for by in struct.pack('!h',i))
                # float_value = struct.unpack('!e', bytes.fromhex(hex(int(binary_str, 2))[2:].zfill(4)))[0]
                log_i = int(math.log2(1+2**(i/SCALING_FACTOR))*SCALING_FACTOR)  
                print(log_i,end='   ')
                # log_i_str=int_to_binary(float_value=log_i)
                log_i_str=''.join(format(by,'08b') for by in struct.pack('!h',log_i))
                print(log_i_str)
                self.controller.table_add('get_log_m_0_table','get_log_m_0_action',['0b'+binary_str],['0b'+log_i_str])  
            except:
                print('Table: get_log_m_0_table, error at',i)     
        
        
        '''
        action get_log_m_1_action(int<16> log_m) {
            ig_md.ac_md.log_m = log_m;
        }

        action log_k_zero_1_action() {
            hdr.calc.z = 0;
            exit;          
        }

        table get_log_m_1_table {
            key = {
            ig_md.ac_md.log_k : exact;
            }
            actions = {
                get_log_m_1_action;
                log_k_zero_1_action;
            }

            default_action = log_k_zero_1_action();
            size = 32768; 
        }
        '''
        for i in range(1,2**16):
            try:
                print(-1*i,end='   ')
                # binary_str = bin(i)[2:].zfill(16)
                # binary_str = '1'+binary_str[1:]
                binary_str = ''.join(format(by,'08b') for by in struct.pack('!h',-1*i))
                
                print(binary_str)
                # float_value = struct.unpack('!e', bytes.fromhex(hex(int(binary_str, 2))[2:].zfill(4)))[0]
                log_i = int(math.log2(1-2**(-1*(i/SCALING_FACTOR)))*SCALING_FACTOR)
                print(log_i,end='  ')
                # log_i_str=int_to_binary(float_value=log_i)
                log_i_str = ''.join(format(by,'08b') for by in struct.pack('!h',log_i))
                
                print(log_i_str)
                self.controller.table_add('get_log_m_1_table','get_log_m_1_action',['0b'+binary_str],['0b'+log_i_str])
            except:
                print('Table: get_log_m_1_table, error at',i)     
                
        
        '''
        action get_log_m_2_action(int<16> log_m) {
            ig_md.ac_md.log_m = log_m;
        }

        action log_k_zero_2_action() {
            hdr.calc.z = 0;
            exit;          
        }

        table get_log_m_2_table {
            key = {
            ig_md.ac_md.log_k : exact;
            }
            actions = {
                get_log_m_2_action;
                log_k_zero_2_action;
            }

            default_action = log_k_zero_2_action();
            size = 32768; 
        }
        '''
        for i in range(1,int(129*SCALING_FACTOR)):
            try:
                print(i,end='   ')
                # binary_str = bin(i)[2:].zfill(16)
                # binary_str = '0'+binary_str[1:]
                binary_str = ''.join(format(by,'08b') for by in struct.pack('!h',i))
                print(binary_str)
                # float_value = struct.unpack('!e', bytes.fromhex(hex(int(binary_str, 2))[2:].zfill(4)))[0]
                log_i = int(math.log2(-1+2**(i/SCALING_FACTOR))*SCALING_FACTOR)
                print(log_i,end='  ')
                # log_i_str=int_to_binary(float_value=log_i)
                log_i_str = ''.join(format(by,'08b') for by in struct.pack('!h',log_i))
                
                print(log_i_str)
                self.controller.table_add('get_log_m_2_table','get_log_m_2_action',['0b'+binary_str],['0b'+log_i_str])
            except:
                # print('error at',i)
                print('Table: get_log_m_2_table, error at',i)     
                
            
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
        # for i in range(0,int(15*SCALING_FACTOR)):
        for i in range(-1*int(15*SCALING_FACTOR),int(15*SCALING_FACTOR)):
            try:
                print(i,end='   ')
                # binary_str = bin(i)[2:].zfill(16)
                binary_str = ''.join(format(by,'08b') for by in struct.pack('!h',i))
                print(binary_str)
                # float_value = struct.unpack('!e', bytes.fromhex(hex(int(binary_str, 2))[2:].zfill(4)))[0]
                # exp_i = math.log2(1-2**float_value)
                # print(float_value)
                exp_i = 2**(i*1.0/SCALING_FACTOR)*1.0
                # exp_i_str=float_to_binary(float_value=exp_i)
                exp_i_str=''.join(format(by,'08b') for by in struct.pack('!e',exp_i))
                print(exp_i,end='   ')
                print(exp_i_str)
                print() 
                self.controller.table_add('get_abs_z_table','get_abs_z_action',['0b'+binary_str],['0b'+exp_i_str])
            except:
                print('Table: get_abs_z_table, error at',i)     
                
                
            
        
        
        # self.get_table_configuration()
        # self.add_entry_to_tables()
        
        
if __name__ == '__main__':
    con = L2Controller('s1')
    con.run_test()
        