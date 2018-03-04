#include "importdialog.h"
#include "ui_importdialog.h"

ImportDialog::ImportDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ImportDialog)
{
    ui->setupUi(this);
}

ImportDialog::~ImportDialog()
{
    ui->keyInput->setText(QString(" ").repeated(ui->keyInput->text().size()));
    delete ui;
}

secure::string ImportDialog::getKeyData()
{
    secure::string strKeyData;
    strKeyData.reserve(1024);
    strKeyData.assign(ui->keyInput->text().toStdString().c_str());
    return strKeyData;
}

void ImportDialog::hideNewKeyLabel()
{
    ui->importDescription2->setHidden(true);
}
