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
//    static void ShowRawData()
    static QStandardItemModel *detailModel;
};

#endif // DETAILTREEVIEW_H
