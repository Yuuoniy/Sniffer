#include "detailtreeview.h"

DetailTreeView::DetailTreeView()
{
}
QStandardItemModel *DetailTreeView::detailModel = new QStandardItemModel;

void DetailTreeView::Setup()
{

    detailModel->clear();
    detailModel->setColumnCount(1);
    detailModel->setHeaderData(0, Qt::Horizontal, "捕获数据分析：");
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
    frame_layer,
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
    item->appendRow(new QStandardItem(snifferData->protoInfo.strNextProto));
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
}
void DetailTreeView::addAppInfo(const SnifferData *snifferData)
{
    if (snifferData->protoInfo.strAppProto == "")
        return;
    QStandardItem *item, *itemChild;
    item = new QStandardItem(snifferData->protoInfo.strAppProto);
    detailModel->setItem(application_layer, item);
}
