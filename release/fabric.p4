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
            0xFFFF:  parse_customHeader;
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
    /*bool dropped = false;

    action drop_action() {
        mark_to_drop(standard_metadata);
        dropped = true;
    }

    action to_port_action(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    


    table fd_table {
        key = {
            meta.fwdAddr: lpm;
        }
        actions = {
            drop_action;
            to_port_action;
        }
        size = 1024;
        default_action = drop_action;
    }*/
    
    bit<32> packetColor = 0;
    
    bool dropped = false;
   
    direct_meter<bit<32>>(MeterType.packets) customMeter;
    
     action drop_action() {
        mark_to_drop(standard_metadata);
        dropped = true;
    }
    
    action add_color(){
        customMeter.read(packetColor);
    }
    
    
    table red_table{
        key = {
            packetColor:exact;}
        actions={
            NoAction;
            drop_action;
        }
        size = 1024;
        default_action = NoAction;
    }
    
     table color_table{
        key = {
            hdr.customHeader.tenantid:exact;}
        actions={
            add_color;
            NoAction;

        }
        meters = customMeter;
        size = 1024;
        default_action = NoAction;
    }


    apply {
         standard_metadata.egress_spec = (bit<9>)hdr.customHeader.dst_switchid;
         color_table.apply();
         red_table.apply();
        //fd_table.apply();
        
        //if (dropped) return;
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

