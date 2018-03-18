#ifndef IMPORTDIALOG_H
#define IMPORTDIALOG_H

#include <QDialog>
#include "secure.h"

namespace Ui {
class ImportDialog;
}

class ImportDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ImportDialog(QWidget *parent = nullptr);
    secure::string getKeyData();
    void hideNewKeyLabel();
    ~ImportDialog();

private:
    Ui::ImportDialog *ui;
};

#endif // IMPORTDIALOG_H
