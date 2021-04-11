#include "captureThread.h"
#include <QString>
#include <string>
#include "global.h"
#include "packet.h"
#include "../process_protocol.h"
using std::string;
extern QList<string> devicesName;
extern int interface_selected;
extern char errbuf[PCAP_ERRBUF_SIZE];
extern QString captureFilterString;

CaptureThread::CaptureThread()
{
    isStopped = false;
}



CaptureThread::~CaptureThread() {}

void CaptureThread::stop()
{
    isStopped = true;
}

void CaptureThread::run()
{
    pcap_t *adhandle;
    int res;
    const char *name = devicesName.at(interface_selected).c_str();
    // Open the adapter
    if ((adhandle = pcap_open(name,                      // name of the device
                              65536,                     // portion of the packet to capture.
                              PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode (nonzero means promiscuous)
                              1000,                      // read timeout
                              NULL,
                              errbuf // error buffer
                              )) == NULL)
    {
        QMessageBox::warning(0, "Warning!", "\nUnable to open the adapter. " + QString(name) + " is not supported by WinPcap\n");
        return;
    }
    while (!isStopped)
    {
        struct pcap_pkthdr *header = NULL;
        const u_char *data = NULL;

        res = pcap_next_ex(adhandle, &header, &data);
        qDebug() << res;
        if (res > 0 && header != NULL && data != NULL)
        {
            processPacket(header, data);
            

            
        }

    } // while stopped
    isStopped = false;
    qDebug() << "emit CaptureStopped";
    return;
}
