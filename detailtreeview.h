#ifndef DETAILTREEVIEW_H
#define DETAILTREEVIEW_H

#include <QStandardItemModel>
#include "protocol.h"

class DetailTreeView
{
public:
    DetailTreeView();
    static void Setup();
    static void ShowTreeAnalyseInfo(const SnifferData *snifferData);
    static void addFrameInfo(const SnifferData *snifferData);
    static void addEthernetInfo(const SnifferData *snifferData);

    static void addNetworkInfo(const SnifferData *snifferData);

    static void addTransInfo(const SnifferData *snifferData);

    static void addAppInfo(const SnifferData *snifferData);
    static void addTCPInfo(QStandardItem *item, const SnifferData *snifferData);
    static void addUDPInfo(QStandardItem *item, const SnifferData *snifferData);
    static QStandardItemModel *detailModel;
};

#endif // DETAILTREEVIEW_H
