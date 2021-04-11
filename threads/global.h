#ifndef GLOBAL_H
#define GLOBAL_H
#include "packet.h"
#include <QVector>

class Global
{
public:
    Global();
    static QVector<Packet> packets;
};

#endif // GLOBAL_H
