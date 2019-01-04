#ifndef WALLETMAIN_H
#define WALLETMAIN_H

#include "watchdog.h"

#include <QMainWindow>
#include <QLabel>
#include <QtWebSockets/QWebSocket>
#include <QtNetwork/QSslError>
#include <QtCore/QList>
#include <QtCore/QUrl>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QMenu>

#include <ripple/protocol/PublicKey.h>

#include "encryption.h"
#include "errors.h"
#include "msgkind.h"
#include "keymanagement.h"

namespace Ui {
class WalletMain;
}

class WalletMain : public QMainWindow
{
    Q_OBJECT

public:
    explicit WalletMain(QWidget *parent = nullptr);
    ~WalletMain();

private Q_SLOTS:
    // Network events
    void onConnected();
    void doReconnect();
    void onConnectionError(QAbstractSocket::SocketError psError);
    void onTextMessageReceived(QString psMsg);

    // Transaction form actions
    void on_clearButton_clicked();
    void on_previewButton_clicked();
    void on_sendButton_clicked();

    // Menu actions
    void on_actionExit_triggered();
    void on_actionImport_key_triggered();
    void on_actionExport_key_triggered();
    void on_actionGenerateNew_triggered();
    void on_actionEncrypt_wallet_triggered();
    void on_actionCopy_account_address_triggered();
    void on_actionReconnect_triggered();
    void on_actionAbout_triggered();

    // Transaction history actions
    void txItemClicked(int pnRow, int pnCol);

    void on_actionSwitch_account_triggered();
    void on_actionProxy_triggered();

private:

    typedef std::vector<std::vector<QString> > TxVector;

    // Client UI pointer
    Ui::WalletMain *ui;

    QLabel balanceLabel;
    QLabel ledgerLabel;
    QLabel networkStatusLabel;

    // WebSocket connection
    QWebSocket wSockConn;
    int nConnectAttempt = 0;

    // RPC Request ID
    int nRequestID = 1;

    // Fees
    int64_t nFee = 1, nFeeRef = 1, nReserve = 10;

    int64_t nIndex = -1, nCloseTime = 0;
    QString sHash;
    int nTxes = 0;

    // Wallet data
    int nDeriveIterations = 0;
    std::string sMasterPubKey;
    std::vector<unsigned char> vchDerivationSalt;
    std::vector<unsigned char> vchCryptedMasterKey;

    size_t nMainAccount = 0;
    std::vector<KeyData> vkStore;
    QJsonArray vsAccounts;
    std::vector<int64_t> vnBalances;
    std::vector<int> vnSequences;
    std::vector<TxVector> vtTransactions;

    // RPC request map
    std::map<int, MessageType> nmReqMap;

    // ================= //

    // Connect to random server
    void socketConnect();

    // Update GUI to show new connection status
    void setOnline(bool pbFlag = true, const QString& psReason = "OK");


    // Response handlers

    void accInfoResponse(const QJsonObject& poResp);
    void accTxResponse(const QJsonObject& poResp);
    void submitResponse(const QJsonObject& poResp);
    void subsLedgerAndAccountResponse(const QJsonObject& poResp);

    // Request handlers
    void accInfoRequest(QJsonArray poAccs = {});
    void accTxRequest(QJsonArray poAccs = {});
    void submitRequest(QString hexBlobData);
    void subsLedgerAndAccountRequest();

    // Key management
    Error loadWallet(QString& psAccID);
    Error processWalletEntry(const QJsonObject& poKey, KeyData& pkData);
    Error processWallet(const QJsonObject& poKey);
    Error convertLegacyWallet(const QJsonObject& poKey);
    void saveKeys(bool pbOverwrite=false);
    Error newKey(QString& psNewAccID);
    Error importKey(const secure::string& psKey, QString& psNewAccID);
    Error exportKey(QString& psKey);

    // Ask for password
    Error askPassword();

    // Create and sign transaction
    Error createPaymentTx(const QString& psRecvAcc, std::int64_t pnAmount, std::int64_t pnTxFee, std::int64_t pnTagID, QString& psJson, QString& psHex);

    // Adjust element layout
    void setupControls(QWidget *parent);

    // Add transaction to table
    void processTxMessage(QJsonObject poTxn);

    // Pull records from vector to data grid
    void refreshTxView();

    // Check if tx has been processed already
    bool txExists(QString strTxId, size_t nAccountId);

    // Process ledger info
    void processLedgerMessage(QJsonObject poLedger);

    // Create and send payment
    void sendPayment(bool pbJustAsk=true);
};

#endif // WALLETMAIN_H
