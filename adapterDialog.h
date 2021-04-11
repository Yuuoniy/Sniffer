#ifndef ADAPTERDIALOG_H
#define ADAPTERDIALOG_H

#include <QDialog>

namespace Ui {
class AdapterDialog;
}

class AdapterDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AdapterDialog(QWidget *parent = nullptr);
    explicit AdapterDialog();
    ~AdapterDialog();

private:
    Ui::AdapterDialog *ui;
};

#endif // ADAPTERDIALOG_H
