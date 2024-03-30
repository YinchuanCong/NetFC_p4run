#include<core.p4>
#include<v1model.p4>

//-------------------------------------------------------------------------------       Headers------------------------------//
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> etherType;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> etherType;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header calc_h {
    bit<16> x;
    bit<16> y;
    bit<16> z;
    bit<16> protocol;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header time_t {
    bit<16> timestamp;
    bit<16>  protocol;
    // bit<16> t1;
    // bit<16> t2;
}

struct digest_info{
    bit<16> x;
    bit<16> y;
    bit<16> z;
    bit<16> t;
}

struct header_t {
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    ipv4_h ipv4;
    ipv6_h ipv6;
    tcp_h tcp;
    udp_h udp;

    calc_h calc;
    // Add more headers here.
    time_t time;
}

struct empty_header_t {}

struct empty_metadata_t {}

// ---------------------------------------------------------------------------
//                             Approximate Calculation
// z=x+y 
// frac_z=z, frac_x=|x|, frac_y=|y|
// log_i=log(frac_x), log_j=log(frac_y)
// log_k=log_j-log_i
// log_m=log(±1±2^(j-i))
// n=i+log(±1±2^(j-i))
// sign_z=0x0 if z>0 else sign_z=0x8000  
// info: ___________________________ ______ _____ _________  
//      |  five bits reserved       |  x>0 | y>0 | |x|>|y| |      let 0 be ture, and 1 be false 
//      |___________________________|______|_____|_________|
// flag:
//      x+y= ±2^(i+log(±1±2^(j-i)))
//      the first two bits of flag correspond to the last two ±, and the others are reserved. 
// ---------------------------------------------------------------------------
struct approximate_calculation_metadata_t {
    bit<16> frac_x;
    bit<16> frac_y;
    bit<16> sign;
    bit<16> frac_z;

    bit<16> log_i;
    bit<16> log_j;
    bit<16> log_k;
    bit<16> log_m;
    bit<16> n;


    bit<16> sign_z;
    bit<8>  info;
    bit<8>  flag;
    // bit<16> pad; /////////////
    digest_info d_info;
    // time_t time;
}

struct metadata_t {approximate_calculation_metadata_t ac_md;}

//------------------------------------------------------------------------------------  end of headers ------------------------//



parser ParserImpl(packet_in packet, out header_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
                 0: parse_time;
                 3: parse_calc;
            default: accept;
        }
    }

    state parse_calc{
        packet.extract(hdr.calc);
        transition select((bit<8>)hdr.calc.protocol){
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
                0 : parse_time;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    state parse_time {
        packet.extract(hdr.time);
        transition select((bit<8>)hdr.time.protocol) {
            // 8w0x6: parse_tcp;
            8w0x06: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    state start {
        transition parse_ethernet;
    }
}

control egress(inout header_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    // action rewrite_mac(bit<48> smac) {
    //     hdr.ethernet.srcAddr = smac;
    // }
    // action _drop() {
    //     mark_to_drop(standard_metadata);
    // }
    // table send_frame {
    //     actions = {
    //         rewrite_mac;
    //         _drop;
    //     }
    //     key = {
    //         standard_metadata.egress_port: exact;
    //     }
    //     size = 256;
    // }
    apply {
        // send_frame.apply();
    }
}

control ingress(inout header_t hdr, inout metadata_t ig_md, inout standard_metadata_t standard_metadata){

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table dmac {
        key ={hdr.ipv4.dst_addr: lpm;}
        actions = {
            forward;
            drop;
        }
        default_action = drop();
    }

    action get_info_action(bit<8> info) {
        // ig_md.ac_md.info = info;
        ig_md.ac_md.info[2:2]=hdr.calc.x[15:15];
        ig_md.ac_md.info[1:1]=hdr.calc.y[15:15];
        ig_md.ac_md.info[0:0]=ig_md.ac_md.sign[15:15];
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
        default_action = get_info_action(0);
        size = 8;
    }

    action get_log_i_action(bit<16> log_i) {
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

    action get_log_j_action(bit<16> log_j) {
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

    action get_log_m_0_action(bit<16> log_m) {
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
    

    action get_log_m_1_action(bit<16> log_m) {
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

    action get_log_m_2_action(bit<16> log_m) {
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

    apply {
        dmac.apply();

        ig_md.ac_md.frac_x = (bit<16>) hdr.calc.x[14:0];
        ig_md.ac_md.frac_y = (bit<16>) hdr.calc.y[14:0];
        ig_md.ac_md.sign = (bit<16>)((int<16>)ig_md.ac_md.frac_x - (int<16>)ig_md.ac_md.frac_y);   
        get_info_table.apply();

        // ig_md.ac_md.d_info.y = (bit<16>)ig_md.ac_md.info;


        // ig_tm_md.ucast_egress_port = 130;
        // ig_tm_md.bypass_egress = 1w1;

        get_log_i_table.apply();
        get_log_j_table.apply();


        // ig_md.ac_md.d_info.x = ig_md.ac_md.log_i;
        // ig_md.ac_md.d_info.y = ig_md.ac_md.log_j;
        // ig_md.ac_md.d_info.z = hdr.calc.z;
        // digest<digest_info>(1,ig_md.ac_md.d_info);



        // if(ig_md.ac_md.log_j > ig_md.ac_md.log_i)  // j -i
        // {
        //     ig_md.ac_md.log_k = ig_md.ac_md.log_j - ig_md.ac_md.log_i;
        // }
        // else{
        //     ig_md.ac_md.log_k = (~(ig_md.ac_md.log_i - ig_md.ac_md.log_j)+(bit<16>)1)|0b1000000000000000;
        // }
        ig_md.ac_md.log_k = (bit<16>)((int<16>)ig_md.ac_md.log_j - (int<16>)ig_md.ac_md.log_i);

        ////2024年3月9日12:33:09 




        switch(get_flag_table.apply().action_run) {
            set_flag_0_action: { get_log_m_0_table.apply(); } //log_m = log(1+2^(j-i))
            set_flag_1_action: { get_log_m_1_table.apply(); } //log_m = log(1-2^(j-i))
            set_flag_2_action: { get_log_m_2_table.apply(); } //log_m = log(-1+2^(j-i)) 
        }


        // ig_md.ac_md.d_info.x = ig_md.ac_md.log_k;
        // ig_md.ac_md.d_info.y = ig_md.ac_md.log_m;
        // // ig_md.ac_md.d_info.z = ;
        // digest<digest_info>(1,ig_md.ac_md.d_info);
        

        // ig_md.ac_md.d_info.x[15:15] = hdr.calc.x[15:15];
        // ig_md.ac_md.d_info.y[15:15] = hdr.calc.y[15:15];
        // ig_md.ac_md.d_info.z[15:15] = ig_md.ac_md.sign[15:15];\
       

        
        ig_md.ac_md.n = ig_md.ac_md.log_i + ig_md.ac_md.log_m;
        get_abs_z_table.apply();
        hdr.calc.z = hdr.calc.z | ig_md.ac_md.sign_z;

        ig_md.ac_md.d_info.x=(bit<16>)hdr.calc.x;
        ig_md.ac_md.d_info.y=(bit<16>)hdr.calc.y;
        ig_md.ac_md.d_info.z=hdr.calc.z;





        // ig_md.ac_md.d_info.x = hdr.calc.x;
        // ig_md.ac_md.d_info.y = hdr.calc.y;
        // ig_md.ac_md.d_info.z = hdr.calc.z;

        // ig_md.ac_md.d_info.z = (bit<16>)ig_md.ac_md.info; // test for get_info_table

        // ig_md.ac_md.d_info.x = (bit<16>)ig_md.ac_md.log_i;  // test for get_log_i_table
        // ig_md.ac_md.d_info.y = (bit<16>)ig_md.ac_md.log_j;
        
        // ig_md.ac_md.d_info.z = (bit<16>)hdr.calc.z;
        // ig_md.ac_md.d_info.z = (bit<16>)2 - (bit<16>)4;


        

        digest<digest_info>(1,ig_md.ac_md.d_info);
    }

}


control DeparserImpl(packet_out packet, in header_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);

        packet.emit(hdr.time);

        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout header_t hdr, inout metadata_t meta) {
    apply {
        // verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout header_t hdr, inout metadata_t meta) {
    apply {
        // update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}


V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
