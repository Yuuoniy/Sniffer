#include "adapterDialog.h"
#include "ui_adapterDialog.h"
#include <QStandardItemModel>
#include <QMessageBox>
#include <QList>
#include <QModelIndex>
#include <pcap.h>

//QList<QString> devicesName;
AdapterDialog::AdapterDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AdapterDialog)
{
    ui->setupUi(this);
}

AdapterDialog::~AdapterDialog()
{
    delete ui;
}


AdapterDialog::AdapterDialog() :
    ui(new Ui::AdapterDialog)
{
    ui->setupUi(this);
}
