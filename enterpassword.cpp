#include "enterpassword.h"
#include "ui_enterpassword.h"

EnterPassword::EnterPassword(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EnterPassword)
{
    ui->setupUi(this);
}

EnterPassword::~EnterPassword()
{
    delete ui;
}

QString EnterPassword::getPassword()
{
    return ui->passwordInput->text();
}
