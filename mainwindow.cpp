#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QMessageBox>
#include <QList>
#include <QModelIndex>
#include <string>
#include <QHeaderView>
#include <QListWidget>
#include <QComboBox>
#include <QSplitter>
#include <ctype.h>
#include <pcap.h>
#include "threads/captureThread.h"

using std::string;

QList<string> devicesName;
char errbuf[PCAP_ERRBUF_SIZE];
int interface_selected;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    QFont font = QFont("Consolas", 10);
    this->setFont(font);
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        QMessageBox::warning(this, "Error in pcap_findalldevs_ex: %s\n", errbuf);
    }
    /* Print the list */
    for (d = alldevs; d; d = d->next, i++)
    {

        devicesName.push_back(d->name);
        // QStandardItem *adapter = new QStandardItem(QString(d->name));
        ui->comboBox->addItem(d->description);
        qDebug(d->name);
    }
    ui->stopButton->setDisabled(true);
    ui->packetTableView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->packetTableView->verticalHeader()->hide();
    ui->packetTableView->setModel(PacketsListView::PacketModel);
    ui->packetTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    ui->detailTreeView->setModel(DetailTreeView::detailModel);
    ui->clearButton->setDisabled(false);
    QObject::connect(ui->packetTableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)), this, SLOT(addDataToWidget(const QItemSelection &)));
    connect(ui->startButton, SIGNAL(clicked()), this, SLOT(startCapture()));
    connect(ui->stopButton, SIGNAL(clicked()), this, SLOT(stop()));
    connect(ui->filterButton, SIGNAL(clicked()), this, SLOT(setFilterString()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clearFilterString()));
    ui->textEdit->setStyleSheet("QTextEdit {margin-left:0px; margin-right:0px}");
    // ui->textEdit.setStyleSheet("QTextEdit {margin-left:0px; margin-right:0px}");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::Helloworld()
{
    QMessageBox::warning(0, "hello", "hello");
}

void MainWindow::setFilterString()
{
    Global::filter = ui->filterlineEdit->text();
    ui->clearButton->setDisabled(false);
}

void MainWindow::clearFilterString()
{
    Global::filter = "";
    ui->filterlineEdit->setText("");
    ui->clearButton->setDisabled(true);
}
void MainWindow::startCapture()
{

    QString adapter_name = ui->comboBox->currentText();
    interface_selected = ui->comboBox->currentIndex();
    qDebug() << "adapter_name " << adapter_name << " idx " << interface_selected;

    if (interface_selected == -1)
    {
        QMessageBox::warning(this, "Select a interface", "Please select a interface first\n");
        return;
    }

    if (!capture.isRunning())
    {
        capture.start();
    }

    ui->startButton->setDisabled(true);
    ui->stopButton->setDisabled(false);
}

void MainWindow::stop()
{
    ui->stopButton->setDisabled(true);
    ui->startButton->setDisabled(false);
    capture.stop();
}

QString generateOutputFromData(unsigned char *data, int len)
{

    QString hexText = QString("0010  ");
    QString asciiText = QString("");
    char buf[6];
    char ch;
    memset(buf, 0, 6);
    for (int i = 1; i < len + 1; i++)
    {
        sprintf(buf, "%.2x ", data[i - 1]);
        hexText += QString(buf);
        ch = data[i - 1];
        if (isprint(ch))
        {
            asciiText += ch;
        }
        else
        {
            asciiText += '.';
        }
        if ((i % 16) == 0)
        {
            hexText += "\t" + asciiText + "\n";
            hexText += QString("%1  ").arg((i / 16 + 1) * 10, 4, 10, QLatin1Char('0'));
            asciiText = "";
        }

        memset(buf, 0, 6);
    }
    return hexText;
}

void MainWindow::addDataToWidget(const QItemSelection &nowSelect)
{
    QModelIndexList items = nowSelect.indexes();
    QModelIndex index = items.first();

    int iNumber = index.row();

    if ((unsigned int)iNumber < Global::packets.size())
    {
        DetailTreeView::ShowTreeAnalyseInfo(&(Global::packets.at(iNumber)));
        QString output;
        int len = Global::packets.at(iNumber).strLength.toInt();

        output = generateOutputFromData(Global::packets.at(iNumber).pkt_data, len);
        ui->textEdit->setText(output);
    }
}
