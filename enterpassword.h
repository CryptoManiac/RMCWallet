#ifndef ENTERPASSWORD_H
#define ENTERPASSWORD_H

#include <QDialog>
#include "encryption.h"

namespace Ui {
class EnterPassword;
}

class EnterPassword : public QDialog
{
    Q_OBJECT

public:
    explicit EnterPassword(QWidget *parent = 0, bool isConfirmation = false);
    ~EnterPassword();
    secure::string getPassword();

private:
    Ui::EnterPassword *ui;
};

#endif // ENTERPASSWORD_H
