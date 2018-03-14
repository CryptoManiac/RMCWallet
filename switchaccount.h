#ifndef SWITCHACCOUNT_H
#define SWITCHACCOUNT_H

#include <QDialog>

namespace Ui {
class SwitchAccount;
}

class SwitchAccount : public QDialog
{
    Q_OBJECT

public:
    explicit SwitchAccount(QWidget *parent = 0, const QVariantList& accounts = {}, int nCurrentAccount = 0);
    ~SwitchAccount();
    int getSelected();

private:
    Ui::SwitchAccount *ui;
};

#endif // SWITCHACCOUNT_H
