#ifndef WALLETMAIN_H
#define WALLETMAIN_H

#include <QMainWindow>
#include <QLabel>
#include <QtWebSockets/QWebSocket>
#include <QtNetwork/QSslError>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtCore/QUrl>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QMenu>

#include <ripple/protocol/PublicKey.h>
#include <ripple/protocol/SecretKey.h>

namespace Ui {
class WalletMain;
}

#include "msgkind.h"

struct KeyData {
    ripple::SecretKey secretKey;
    ripple::PublicKey publicKey;
    std::vector<unsigned char> encryptedKey;
    std::vector<unsigned char> salt;
    int nDeriveIterations = 0; // zero means absence of encryption
    ripple::AccountID accountID;
};

class WalletMain : public QMainWindow
{
    Q_OBJECT

public:
    explicit WalletMain(QWidget *parent = 0);
    ~WalletMain();

private Q_SLOTS:
    // Network events
    void onConnected();
    void doReconnect();
    void onConnectionError(QAbstractSocket::SocketError error);
    void onTextMessageReceived(QString message);

    // Transaction form actions
    void on_clearButton_clicked();
    void on_previewButton_clicked();
    void on_sendButton_clicked();

    // Menu actions
    void on_actionExit_triggered();
    void on_actionReinitializeWallet_triggered();
    void on_actionImport_key_triggered();
    void on_actionExport_key_triggered();
    void on_actionEncrypt_wallet_triggered();
    void on_actionCopy_account_address_triggered();
    void on_actionReconnect_triggered();
    void on_actionAbout_triggered();

    // Transaction history actions
    void txItemClicked(int nRow, int nCol);

private:
    // Client UI pointer
    Ui::WalletMain *ui;

    QLabel balanceLabel;
    QLabel ledgerLabel;
    QLabel networkStatusLabel;

    // WebSocket connection
    QWebSocket m_webSocket;
    int nConnectAttempt = 0;

    // Wallet data
    KeyData keyData;

    // RPC Request ID
    int nRequestID = 1;

    // Fee and sequence
    int64_t nFee = 10;
    int64_t nFeeRef = 10;
    int64_t nReserve = 2500;
    int64_t nBalance = 0;
    int64_t nLedger = -1;
    int64_t nSequence = 0;

    QString ledgerHash;
    int64_t ledgerCloseTime;
    int ledgerTransactions;

    // RPC request map
    std::map<int, MessageType> reqMap;

    // ================= //

    // Connect to random server
    void socketConnect();

    // Check internet availability
    bool isNetworkAvailable();

    // Update GUI to show new connection status
    void setOnline(bool flag = true, const QString& reason = "OK");


    // Response handlers

    void accInfoResponse(QJsonObject obj);
    void accTxResponse(QJsonObject obj);
    void submitResponse(QJsonObject obj);
    void subsLedgerAndAccountResponse(QJsonObject obj);

    // Request handlers
    void accInfoRequest();
    void accTxRequest();
    void submitRequest(QString hexBlobData);
    void subsLedgerAndAccountRequest();

    // Key management
    bool loadWallet(QString& errStr);
    void saveKeys();
    void newKey();
    bool importKey(const QString& keyData);
    QString exportKey(QString& errorMsg);

    // Ask for password
    bool askPassword(QString& errorMsg);

    // Create and sign transaction
    bool createPaymentTx(const QString& receiverAccount, std::int64_t nAmount, std::int64_t nTransactionFee, std::int64_t nDestinationID, QString& dataJson, QString& dataHex, QString&errorMsg);

    // Adjust element layout
    void setupControls(QWidget *parent);

    // Add transaction to table
    void processTxMessage(QJsonObject txObj);

    // Process ledger info
    void processLedgerMessage(QJsonObject ledgerObj);
};

#endif // WALLETMAIN_H
