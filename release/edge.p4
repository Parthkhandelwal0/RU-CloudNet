/* Minimal P4 skeleton code adapted from example in
  https://opennetworking.org/news-and-events/blog/getting-started-with-p4/
*/

#include <core.p4>
#include <v1model.p4>

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;

/* HEADER DEFINITIONS */

header ethernet_t {
    EthernetAddress dst_addr;
    EthernetAddress src_addr;
    bit<16>         ether_type;
}

header customHeader_t{
    bit<16> custom_ether_type; //custom ethertype
    bit<16> dst_switchid; //destination switch identifier
    bit<16> tenantid;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    IPv4Address src_addr;
    IPv4Address dst_addr;
}

header arp_t {
    bit<16>     hrtype; //hardware type
    bit<16>     ptype; //protocol type
    bit<8>      hrlen; //hardware address length
    bit<8>     plen;  //protocol address length
    bit<16>     operation;
    EthernetAddress      sha; //sender hardware address
    EthernetAddress      tha; //target hardware address
    IPv4Address spa; //sender protocol address
    IPv4Address tpa; //target protocol address
}

struct headers_t {
    ethernet_t ethernet;
    customHeader_t customHeader;
    ipv4_t     ipv4;
    arp_t arp;
}

struct metadata_t {
    IPv4Address fwdAddr;
}

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported
}

/* PARSER */

parser my_parser(packet_in packet,
                out headers_t hd,
                inout metadata_t meta,
                inout standard_metadata_t standard_meta)
{
    state start {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.ether_type) {
            0x0800:  parse_ipv4;
            0x0806:  parse_arp; 
            0xFFFF: parse_customHeader;
            default: accept;
        }
    }
    
    state parse_customHeader{
        packet.extract(hd.customHeader);
        transition select(hd.customHeader.custom_ether_type) {
            0x0800:  parse_ipv4;
            0x0806:  parse_arp; 
            default: accept;
        }
    }
    
    state parse_arp{
    packet.extract(hd.arp);
    meta.fwdAddr = hd.arp.tpa;
    transition accept;
    }

    state parse_ipv4 {
        packet.extract(hd.ipv4);
        verify(hd.ipv4.version == 4w4, error.IPv4IncorrectVersion);
        verify(hd.ipv4.ihl == 4w5, error.IPv4OptionsNotSupported);
        meta.fwdAddr = hd.ipv4.dst_addr;
        transition accept;
    }    
}

/* DEPARSER */

control my_deparser(packet_out packet,
                   in headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.customHeader);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);

    }
}

/* CHECKSUM CALCULATION AND VERIFICATION */

control my_verify_checksum(inout headers_t hdr,
                         inout metadata_t meta)
{
    apply { }
}

control my_compute_checksum(inout headers_t hdr,
                          inout metadata_t meta)
{
    apply { }
}

/* INGRESS PIPELINE */

control my_ingress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata)
{
    bool dropped = false;
    bool fd_hit = false;

    action drop_action() {
        mark_to_drop(standard_metadata);
        dropped = true;
    }

    action to_port_action(bit<9> port) {
        standard_metadata.egress_spec = port;
        fd_hit = true;
        
    }
    
    
    action set_switchid(bit<16> switchid) {
        hdr.customHeader.setValid();
        hdr.customHeader.dst_switchid = switchid;
        hdr.customHeader.tenantid = (bit<16>)standard_metadata.ingress_port;
        standard_metadata.egress_spec = 4;
    }
    
    table switch_table{
        key = {
            meta.fwdAddr: lpm;
        }
        actions = {
            drop_action;
            set_switchid;
        }
        size = 1024;
        default_action = drop_action;
    }

    table fd_table {
        key = {
            meta.fwdAddr: lpm;
        }
        actions = {
            NoAction;
            to_port_action;
        }
        size = 1024;
        default_action = NoAction;
    }

    apply {
        fd_table.apply();
        
        
        if(fd_hit==true){
            if(hdr.customHeader.isValid()){// if the packet comes from fabric switch
                if(standard_metadata.egress_spec == (bit<9>)hdr.customHeader.tenantid){
                hdr.ethernet.ether_type = hdr.customHeader.custom_ether_type;
                hdr.customHeader.setInvalid();
                }
                else{
                    drop_action();
                }
            }else{
                drop_action();}

        }else{
        
            if(hdr.customHeader.isValid()){// if the packet comes from fabric switch
                 //there is no custom header yet because swith_table is not called yet
                //hdr.ethernet.ether_type = hdr.customHeader.custom_ether_type;
                //hdr.customHeader.setInvalid();
                drop_action();
            }
            else{//packet coming from host 
                switch_table.apply();
                
                hdr.customHeader.custom_ether_type = hdr.ethernet.ether_type;
                hdr.ethernet.ether_type = 0xFFFF;
            }
        }
        
        if (dropped) return;
    }
}

/* EGRESS PIPELINE */

control my_egress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{
    apply { }
}

/* SWITCH PACKAGE DEFINITION */

V1Switch(my_parser(),
         my_verify_checksum(),
         my_ingress(),
         my_egress(),
         my_compute_checksum(),
         my_deparser()) main;

