#ifndef PROCESS_PROTOCOL_H
#define PROCESS_PROTOCOL_H

#include "protocol.h"
#include "global.h"

void processPacket(const struct pcap_pkthdr *header, const unsigned char *data);
void processIPPacket(const unsigned char *buffer);
void processARPPacket(const unsigned char *buffer);

void processICMPPacket(const unsigned char *);

void processIGMPPacket(const unsigned char *);

void processUDPPacket(const unsigned char *);

void processTCPPacket(const unsigned char *);

void processETHERNETPacket();

#endif // PROCESS_PROTOCOL_H
