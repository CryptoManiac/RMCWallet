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
    delete ui;
}

QString ImportDialog::getKeyData()
{
    return ui->keyInput->text();
}

void ImportDialog::hideNewKeyLabel()
{
    ui->importDescription2->setHidden(true);
}
