#ifndef IMPORTDIALOG_H
#define IMPORTDIALOG_H

#include <QDialog>

namespace Ui {
class ImportDialog;
}

class ImportDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ImportDialog(QWidget *parent = 0);
    QString getKeyData();
    void hideNewKeyLabel();
    ~ImportDialog();

private:
    Ui::ImportDialog *ui;
};

#endif // IMPORTDIALOG_H
