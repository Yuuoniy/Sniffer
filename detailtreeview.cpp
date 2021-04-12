#include "detailtreeview.h"

DetailTreeView::DetailTreeView()
{
}
QStandardItemModel *DetailTreeView::detailModel = new QStandardItemModel;

void DetailTreeView::Setup()
{

    detailModel->clear();
    detailModel->setColumnCount(1);
    detailModel->setHeaderData(0, Qt::Horizontal, "Data Parse:");
}
void DetailTreeView::ShowTreeAnalyseInfo(const SnifferData *snifferData)
{
    Setup();
    addFrameInfo(snifferData);
    addEthernetInfo(snifferData);
    addNetworkInfo(snifferData);
    addTransInfo(snifferData);
    addAppInfo(snifferData);
}

void DetailTreeView::addFrameInfo(const SnifferData *snifferData)
{
    /* Frame Info */
    //    QString arrivedTime = Globe::capPacket.OIndex->timestamp;
    //    QString devName = Globe::capPacket.OIndex->NAname;
    //    QString packLen = QString::number(Globe::capPacket.OIndex->header.len);
    //    QString frameProto = Globe::capPacket.OIndex->Netpro;
    //    strText = QString("Frame: %1 bytes captured on %2").arg(packLen,devName);
    //    QStandardItem *frameItem = new QStandardItem(strText);
    //    item = new QStandardItem(QString("Interface name: %1").arg(devName));
    //    childItems.push_back(item);
    //    item = new QStandardItem(QString("Encapsulation type: %1").arg(frameProto));
    //    childItems.push_back(item);
    //    item = new QStandardItem(QString("Arrival time: %1").arg(arrivedTime));
    //    childItems.push_back(item);
    //    frameItem->appendRows(childItems);
    //    //rootItem->appendRow(frameItem);
    //    DetailModel->appendRow(frameItem);
}

enum Layers
{
    ethernet_layer,
    network_layer,
    trans_layer,
    application_layer
};

void DetailTreeView::addEthernetInfo(const SnifferData *snifferData)
{
    QStandardItem *item, *itemChild;
    item = new QStandardItem(snifferData->protoInfo.strEthTitle);
    detailModel->setItem(ethernet_layer, item);
    item->appendRow(new QStandardItem(snifferData->protoInfo.strDMac));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strSMac));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strType));
}

// maybe ARP or IP
void DetailTreeView::addNetworkInfo(const SnifferData *snifferData)
{
    QStandardItem *item, *itemChild;
    item = new QStandardItem(snifferData->protoInfo.strNetProto);
    detailModel->setItem(network_layer, item);
    item->appendRow(new QStandardItem(snifferData->protoInfo.strVersion));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strHeadLength));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strLength));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strSIP));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strDIP));
}
void DetailTreeView::addTransInfo(const SnifferData *snifferData)
{
    if (snifferData->protoInfo.strTranProto == "")
        return;
    QStandardItem *item, *itemChild;
    item = new QStandardItem(snifferData->protoInfo.strTranProto);
    detailModel->setItem(trans_layer, item);
    item->appendRow(new QStandardItem(snifferData->protoInfo.strSPort));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strDPort));
    if (snifferData->protoInfo.strTranProto.indexOf("TCP") != -1)
    {
        addTCPInfo(item, snifferData);
    }
    else if (snifferData->protoInfo.strTranProto.indexOf("UDP") != -1)
    {
        addUDPInfo(item, snifferData);
    }
}

void DetailTreeView::addTCPInfo(QStandardItem *item, const SnifferData *snifferData)
{
    //flags:
    QString data_offset = QString::number((ntohs(snifferData->protoInfo.TCP_header->tcp_res) & 0xf000) >> 12);
    u_short flags = ntohs(snifferData->protoInfo.TCP_header->tcp_res) & 0x003f;
    u_short URG = flags & 0x0020;
    u_short ACK = flags & 0x0010;
    u_short PSH = flags & 0x0008;
    u_short RST = flags & 0x0004;
    u_short SYN = flags & 0x0002;
    u_short FIN = flags & 0x0001;
    QString seq_num = QString::number(ntohs(snifferData->protoInfo.TCP_header->seq));
    QString ack_num = QString::number(ntohs(snifferData->protoInfo.TCP_header->ack));
    QString window_size = QString::number(ntohs(snifferData->protoInfo.TCP_header->windsize));
    QString crc = QString::number(ntohs(snifferData->protoInfo.TCP_header->crc));
    QString urgp = QString(ntohs(snifferData->protoInfo.TCP_header->urgp));

    QList<QStandardItem *> childItems;

    childItems.push_back(new QStandardItem(QString("Sequence Number: %1").arg(seq_num)));
    childItems.push_back(new QStandardItem(QString("ACK number: %1").arg(ack_num)));
    childItems.push_back(new QStandardItem(QString("Header length: %1").arg(4 * data_offset.toInt())));
    childItems.push_back(new QStandardItem(QString("Flags: %1").arg(flags)));
    childItems.push_back(new QStandardItem(QString("Window size value: %1").arg(window_size)));
    //    childItems.push_back(new QStandardItem(QString("Urgent pointer: %1").arg(urgp)));
    item->appendRows(childItems);
}

void DetailTreeView::addUDPInfo(QStandardItem *item, const SnifferData *snifferData)
{
    QString length = QString::number(ntohs(snifferData->protoInfo.UDP_header->len));
    QString crc = QString::number(ntohs(snifferData->protoInfo.UDP_header->crc));

    QList<QStandardItem *> childItems;
    childItems.push_back(new QStandardItem(QString("Length: %1").arg(length)));
    childItems.push_back(new QStandardItem(QString("Checksum: %1").arg(crc)));
    item->appendRows(childItems);
}

void DetailTreeView::addAppInfo(const SnifferData *snifferData)
{
    if (snifferData->protoInfo.strAppProto == "")
        return;
    QStandardItem *item, *itemChild;
    item = new QStandardItem(snifferData->protoInfo.strAppProto);
    detailModel->setItem(application_layer, item);
}
