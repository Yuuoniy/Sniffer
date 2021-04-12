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
    QStandardItem *item, *itemChild;
    QModelIndex index;
    item = new QStandardItem(snifferData->protoInfo.strEthTitle);
    detailModel->setItem(0, item);

    item->appendRow(new QStandardItem(snifferData->protoInfo.strDMac));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strSMac));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strType));

    item = new QStandardItem(snifferData->protoInfo.strIPTitle);
    detailModel->setItem(1, item);

    item->appendRow(new QStandardItem(snifferData->protoInfo.strVersion));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strHeadLength));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strLength));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strNextProto));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strSIP));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strDIP));

    item = new QStandardItem(snifferData->protoInfo.strTranProto);
    detailModel->setItem(2, item);

    item->appendRow(new QStandardItem(snifferData->protoInfo.strSPort));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strDPort));

    if (snifferData->protoInfo.strAppProto!=""){
        item = new QStandardItem(snifferData->protoInfo.strAppProto);
        detailModel->setItem(3, item);
    }

}
