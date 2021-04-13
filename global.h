#ifndef GLOBAL_H
#define GLOBAL_H
#include <QVector>
#include <QString>
#include "packet.h"
#include "protocol.h"

class Global
{
public:
    Global();
    static QVector<SnifferData> packets;
    static int printIdx; // this is noted the index show in packet list
    static int szNum;
    static QString filter;
};

#endif // GLOBAL_H
