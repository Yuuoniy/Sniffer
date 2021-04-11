// this file is for process different protocol
// protocol like TCP、UDP、ARP、IGMP、ICMP
#include <QByteArray>
#include "process_protocol.h"
#include "packetslistview.h"

#define LINE_LEN 16

void processPacket(const struct pcap_pkthdr *header, const unsigned char *data)
{
    int i = 0;
    QByteArray rawByteData;
    char szNum[10];
    struct tm *ltime;
    char timestr[16];
    char szLength[6];

    printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
    for (i = 1; (i < header->caplen + 1); i++)
    {
        printf("%.2x ", data[i - 1]);
        if ((i % LINE_LEN) == 0)
            printf("\n");
    }
    SnifferData tmpSnifferData;

    rawByteData.clear();
    rawByteData.setRawData((const char *)data, header->caplen);

    tmpSnifferData.protoInfo.init();

    tmpSnifferData.strData = "原始捕获数据：" + rawByteData.toHex().toUpper();
    sprintf(szNum, "%d", Global::szNum);
    tmpSnifferData.strNum = szNum;
    Global::szNum += 1;
    time_t local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
    tmpSnifferData.strTime = timestr;
    sprintf(szLength, "%d", header->len);
    tmpSnifferData.strLength = szLength;

    ethhdr *eh;
    iphdr *ih;
    udphdr *uh;
    tcphdr *th;
    unsigned short sport, dport;
    unsigned int ip_len, ip_all_len;
    unsigned char *pByte;

    eh = (ethhdr *)data;
    QByteArray DMac, SMac;
    DMac.setRawData((const char *)eh->dest, 6);
    SMac.setRawData((const char *)eh->src, 6);
    DMac = DMac.toHex().toUpper();
    SMac = SMac.toHex().toUpper();

    tmpSnifferData.protoInfo.strDMac = tmpSnifferData.protoInfo.strDMac + DMac[0] + DMac[1] + "-" + DMac[2] + DMac[3] + "-" + DMac[4] + DMac[5] + "-" + DMac[6] + DMac[7] + "-" + DMac[8] + DMac[9] + "-" + DMac[10] + DMac[11];
    tmpSnifferData.protoInfo.strSMac = tmpSnifferData.protoInfo.strSMac + SMac[0] + SMac[1] + "-" + SMac[2] + SMac[3] + "-" + SMac[4] + SMac[5] + "-" + SMac[6] + SMac[7] + "-" + SMac[8] + SMac[9] + "-" + SMac[10] + SMac[11];

    // 获得 IP 协议头
    ih = (iphdr *)(data + SIZE_ETHERNET);

    // 获得 IP 头的大小
    ip_len = (ih->ver_ihl & 0xF) * 4;
    char szSize[6];
    sprintf(szSize, "%u", ip_len);
    tmpSnifferData.protoInfo.strHeadLength += szSize;
    tmpSnifferData.protoInfo.strHeadLength += " bytes";
    ip_all_len = ntohs(ih->tlen);
    sprintf(szSize, "%u", ip_all_len);
    tmpSnifferData.protoInfo.strLength += szSize;
    tmpSnifferData.protoInfo.strLength += " bytes";

    char szSaddr[24], szDaddr[24];
    sprintf(szSaddr, "%d.%d.%d.%d", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);
    sprintf(szDaddr, "%d.%d.%d.%d", ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);

    //    int ether_type = ((struct ethhdr *)data)->type;
    //    switch (ether_type)
    //    {
    //    case 0x0608:
    //        processARPPacket(data + SIZE_ETHERNET);
    //        break;
    //    case 0x0008:
    //        processIPPacket(data + SIZE_ETHERNET);
    //        break;
    //    default:
    //        break;
    //    }

    switch (ih->proto)
    {
    case TCP_SIG:
        tmpSnifferData.strProto = "TCP";
        tmpSnifferData.protoInfo.strNextProto += "TCP (Transmission Control Protocol)";
        tmpSnifferData.protoInfo.strTranProto += "TCP 协议 (Transmission Control Protocol)";
        th = (tcphdr *)((unsigned char *)ih + ip_len);
        sport = ntohs(th->sport); // 获得源端口和目的端口
        dport = ntohs(th->dport);
        if (sport == FTP_PORT || dport == FTP_PORT)
        {
            tmpSnifferData.strProto += " (FTP)";
            tmpSnifferData.protoInfo.strAppProto += "FTP (File Transfer Protocol)";
        }
        else if (sport == TELNET_PORT || dport == TELNET_PORT)
        {
            tmpSnifferData.strProto += " (TELNET)";
            tmpSnifferData.protoInfo.strAppProto += "TELNET";
        }
        else if (sport == SMTP_PORT || dport == SMTP_PORT)
        {
            tmpSnifferData.strProto += " (SMTP)";
            tmpSnifferData.protoInfo.strAppProto += "SMTP (Simple Message Transfer Protocol)";
        }
        else if (sport == POP3_PORT || dport == POP3_PORT)
        {
            tmpSnifferData.strProto += " (POP3)";
            tmpSnifferData.protoInfo.strAppProto += "POP3 (Post Office Protocol 3)";
        }
        else if (sport == HTTPS_PORT || dport == HTTPS_PORT)
        {
            tmpSnifferData.strProto += " (HTTPS)";
            tmpSnifferData.protoInfo.strAppProto += "HTTPS (Hypertext Transfer "
                                                    "Protocol over Secure Socket Layer)";
        }
        else if (sport == HTTP_PORT || dport == HTTP_PORT ||
                 sport == HTTP2_PORT || dport == HTTP2_PORT)
        {
            tmpSnifferData.strProto += " (HTTP)";
            tmpSnifferData.protoInfo.strAppProto += "HTTP (Hyper Text Transport Protocol)";
            tmpSnifferData.protoInfo.strSendInfo = rawByteData.remove(0, 54);
        }
        else
        {
            tmpSnifferData.protoInfo.strAppProto += "Unknown Proto";
        }
        break;
    case UDP_SIG:
        tmpSnifferData.strProto = "UDP";
        tmpSnifferData.protoInfo.strNextProto += "UDP (User Datagram Protocol)";
        tmpSnifferData.protoInfo.strTranProto += "UDP 协议 (User Datagram Protocol)";
        uh = (udphdr *)((unsigned char *)ih + ip_len); // 获得 UDP 协议头
        sport = ntohs(uh->sport);                      // 获得源端口和目的端口
        dport = ntohs(uh->dport);
        pByte = (unsigned char *)ih + ip_len + sizeof(udphdr);

        if (sport == DNS_PORT || dport == DNS_PORT)
        {
            tmpSnifferData.strProto += " (DNS)";
            tmpSnifferData.protoInfo.strAppProto += "DNS (Domain Name Server)";
        }
        else if (sport == SNMP_PORT || dport == SNMP_PORT)
        {
            tmpSnifferData.strProto += " (SNMP)";
            tmpSnifferData.protoInfo.strAppProto += "SNMP (Simple Network Management Protocol)";
        }
        else
        {
            tmpSnifferData.protoInfo.strAppProto += "Unknown Proto";
        }
        break;
    default:
        break;
    }

    char szSPort[6], szDPort[6];
    sprintf(szSPort, "%d", sport);
    sprintf(szDPort, "%d", dport);

    tmpSnifferData.strSIP = szSaddr;
    tmpSnifferData.strSIP = tmpSnifferData.strSIP + " : " + szSPort;
    tmpSnifferData.strDIP = szDaddr;
    tmpSnifferData.strDIP = tmpSnifferData.strDIP + " : " + szDPort;

    tmpSnifferData.protoInfo.strSIP += szSaddr;
    tmpSnifferData.protoInfo.strDIP += szDaddr;
    tmpSnifferData.protoInfo.strSPort += szSPort;
    tmpSnifferData.protoInfo.strDPort += szDPort;

    Global::packets.push_back(tmpSnifferData);
    PacketsListView::addPacketItem(tmpSnifferData);
}

void processIPPacket(const unsigned char *data)
{
    struct iphdr *ipheader = (struct iphdr *)(data);
    int ip_header_len = ipheader->tlen;
    switch (ipheader->proto)
    {
    case IPPROTO_TCP:
        processTCPPacket(data + ip_header_len);
        break;
    case IPPROTO_UDP:
        processUDPPacket(data + ip_header_len);
        break;
    case IPPROTO_ICMP:
        processICMPPacket(data + ip_header_len);
        break;
    case IPPROTO_IGMP:
        processIGMPPacket(data + ip_header_len);
        break;
    default:
        break;
    }
}

void processARPPacket(const unsigned char *data) {}

void processICMPPacket(const unsigned char *data)
{
}

void processIGMPPacket(const unsigned char *data)
{
    //    udphdr* udp_header = (udphdr*)data;
}

void processUDPPacket(const unsigned char *data)
{

    udphdr *udp_header = (udphdr *)data;
}
void processTCPPacket(const unsigned char *data)
{
    tcphdr *tcp_header = (tcphdr *)data;
}

void processETHERNETPacket();
