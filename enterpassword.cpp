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
    ui->passwordInput->setText(QString(" ").repeated(ui->passwordInput->text().size()));
    delete ui;
}

secure::string EnterPassword::getPassword()
{
    secure::string strPassword;
    strPassword.reserve(1024);
    strPassword.assign(ui->passwordInput->text().toStdString().c_str());
    return strPassword;
}

