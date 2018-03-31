#ifndef PROXYSETTINGS_H
#define PROXYSETTINGS_H

#include <QDialog>

namespace Ui {
class ProxySettings;
}

class ProxySettings : public QDialog
{
    Q_OBJECT

public:
    explicit ProxySettings(QWidget *parent = 0);
    ~ProxySettings();
    void updateProxy();

private:
    Ui::ProxySettings *ui;
};

#endif // PROXYSETTINGS_H
