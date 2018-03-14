#include "switchaccount.h"
#include "ui_switchaccount.h"
#include <QStringListModel>

SwitchAccount::SwitchAccount(QWidget *parent, const QVariantList& accounts, int nCurrentAccount) :
    QDialog(parent),
    ui(new Ui::SwitchAccount)
{
    ui->setupUi(this);
    QList<QString> accountList;
    for(const auto& account : accounts) accountList << account.toString();
    ui->accountsList->setModel(new QStringListModel(accountList));
    ui->accountsList->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->accountsList->setCurrentIndex(ui->accountsList->model()->index(nCurrentAccount, 0));
}

int SwitchAccount::getSelected()
{
    return ui->accountsList->currentIndex().row();
}

SwitchAccount::~SwitchAccount()
{
    delete ui;
}
