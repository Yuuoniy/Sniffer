#ifndef PACKET_H
#define PACKET_H

#include "protocol.h"

typedef struct Packet
{
    u_long serialnum;//被捕捉序列号
    //u_long len;//数据包长度
    //int captime;//被捕捉时间
    struct pcap_pkthdr header;//包头
    u_char pkt_data[65535];//包中数据
    char timestamp[30];//时戳

    struct ethhdr *ether_header; //以太网首部
    struct iphdr *IPv4_header;//IPv4首部
    struct ipv6hdr *IPv6_header;//IPv6首部
    struct arphdr *ARP_header;//ARP首部

    struct udphdr *UDP_header;//UDP首部
    struct tcphdr *TCP_header;//TCP首部
    struct icmphdr *ICMP_header;//ICMP首部
    Packet(const u_char* data);
 }Packet;



#endif // PACKET_H
