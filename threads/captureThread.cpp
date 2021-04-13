#include "captureThread.h"
#include <QString>
#include <string>
#include "global.h"
#include "packet.h"
#include "protocolprocess.h"
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

int setFilter(pcap_t *fp, QString filter)
{

    if (filter == "")
        return -1;
    struct bpf_program fcode;
    bpf_u_int32 NetMask = 0xffffff;
    //compile the filter
    if (pcap_compile(fp, &fcode, filter.toStdString().c_str(), 1, NetMask) < 0)
    {
        fprintf(stderr, "\nError compiling filter: wrong syntax.\n");
        return -1;
    }
    //set the filter
    if (pcap_setfilter(fp, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter\n");
        return -1;
    }
    return 0;
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

    setFilter(adhandle,Global::filter);
    while (!isStopped)
    {
        struct pcap_pkthdr *header = NULL;
        const u_char *data = NULL;

        res = pcap_next_ex(adhandle, &header, &data);
        qDebug() << res;
        if (res > 0 && header != NULL && data != NULL)
        {
            // processPacket(header, data);
            ProtocolProcess::processPacket(header, data);
        }

    } // while stopped
    isStopped = false;
    qDebug() << "emit CaptureStopped";
    return;
}
