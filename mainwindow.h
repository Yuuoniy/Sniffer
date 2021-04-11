#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "threads/captureThread.h"
#include <QString>
#include <QItemSelection>
#include <QVector>
#include "packetslistview.h"
#include "detailtreeview.h"

QT_BEGIN_NAMESPACE
namespace Ui
{
    class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public slots:
    void Helloworld();
    void startCapture();
    void stop();
    void addDataToWidget(const QItemSelection &nowSelect);

private:
    Ui::MainWindow *ui;
    CaptureThread capture;
    PacketsListView pktltView;
};

#endif // MAINWINDOW_H
