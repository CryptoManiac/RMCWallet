#include <QApplication>
#include <QMessageBox>
#include <QStandardPaths>
#include <QFile>
#include <QDir>
#include <QTimer>
#include <QClipboard>
#include <QtGlobal>
#include <QSslCertificate>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QtNetwork>

#include "walletmain.h"
#include "ui_walletmain.h"
#include "transactionpreview.h"
#include "transactionview.h"
#include "doublevalidator.h"
#include "intvalidator.h"
#include "importdialog.h"
#include "enterpassword.h"
#include "aboutdialog.h"
#include "switchaccount.h"

#include <ripple/protocol/AccountID.h>
#include <ripple/protocol/PublicKey.h>
#include <ripple/protocol/digest.h>
#include <ripple/protocol/HashPrefix.h>
#include <ripple/protocol/JsonFields.h>
#include <ripple/protocol/Sign.h>
#include <ripple/protocol/st.h>
#include <ripple/protocol/TxFlags.h>
#include <ripple/basics/StringUtilities.h>

#include <algorithm>
#include <random>
#include <tuple>

// Helpers

Error noError = Error(E_NONE, "none", "none");
Error noPassword = Error(E_NONE, "password", "password");
Error noWif = Error(E_NONE, "wif", "wif");

inline static QString timeFormat(int64_t nTime)
{
    return QDateTime::fromTime_t(946684800 + nTime).toString("dd/MM/yyyy hh:mm:ss");
}

inline static QString AmountWithSign(int64_t nAmount, bool isDebit = false, QString strCurrency = "RMC")
{
    return QString("%1%2 %3").arg(isDebit ? "-" : "").arg(QString::number ( nAmount / 1000000.0, 'f', 6 )).arg(strCurrency);
}

inline static QString Amount(int64_t nAmount)
{
    return QString::number ( nAmount / 1000000.0, 'f', 6 );
}

inline static int64_t readInt(QLineEdit* lineEdit)
{
    return QLocale::system().toInt(lineEdit->text());
}

inline static double readDouble(QLineEdit* lineEdit)
{
    return QLocale::system().toDouble(lineEdit->text());
}

// Core routines

Error WalletMain::createPaymentTx(const QString& receiverAccount, std::int64_t nAmount, std::int64_t nTransactionFee, std::int64_t nDestinationID, QString& dataJson, QString& dataHex)
{
    using namespace ripple;

    auto const destination = parseBase58<AccountID>(receiverAccount.toStdString());
    if (! destination)
        return Error(E_FATAL, "Payment", "Invalid receiver address");

    if (nAmount <= 0)
        return Error(E_FATAL, "Payment", "You can send only positive amounts.");

    auto& keyData = keyStore[nCurrentAccount];

    STTx noopTx(ttPAYMENT,
                [&](auto& obj)
    {
        // General transaction fields
        obj[sfAccount] = keyData.accountID;
        obj[sfFee] = STAmount{ static_cast<uint64_t>(nTransactionFee) };
        obj[sfFlags] = tfFullyCanonicalSig;
        obj[sfSequence] = sequences[nCurrentAccount];
        obj[sfSigningPubKey] = keyData.publicKey.slice();
        // Payment-specific fields
        obj[sfAmount] = STAmount { static_cast<uint64_t>(nAmount) };
        obj[sfDestination] = *destination;
        if (nDestinationID != 0)
            obj[sfDestinationTag] = nDestinationID;

    });

    try
    {
        auto res = askPassword();
        if (noError != res)
        {
            return res;
        }

        noopTx.sign(keyData.publicKey, keyData.secretKey);
        if (nDeriveIterations != 0)
            keyData.secretKey.~SecretKey();
        dataJson = noopTx.getJson(0).toStyledString().c_str();
        dataHex = strHex(noopTx.getSerializer().peekData()).c_str();
    }
    catch(const std::exception e)
    {
        return Error(E_FATAL, "Payment", e.what());
    }

    return noError;
}

Error WalletMain::processWalletEntry(const QJsonObject& keyObj, KeyData& keyData)
{
    using namespace ripple;

    if (keyObj["account_id"].isUndefined())
        return Error(E_FATAL, "Wallet", "Senseless wallet record found: no account ID");

    auto decodeResult1 = parseBase58<AccountID>(keyObj["account_id"].toString().toStdString());
    if (! decodeResult1)
        return Error(E_FATAL, "Wallet", "Unable to decode your account ID, it looks like your wallet data was corrupted.");

    if (keyObj["private_key"].isUndefined() && keyObj["encrypted_private_key"].isUndefined())
        return Error(E_FATAL, "Wallet", "Senseless wallet record found: no keys data for account " + keyObj["account_id"].toString());

    if (!keyObj["encrypted_private_key"].isUndefined() && keyObj["public_key"].isUndefined())
        return Error(E_FATAL, "Wallet", "Senseless wallet record found: encrypted private key is present, but no public key available for account " + keyObj["account_id"].toString());

    keyData.accountID = *decodeResult1;

    if ( !keyObj["private_key"].isUndefined() && !keyObj["private_key"].isNull())
    {
        // Plain wallet
        auto decodeResult = parseHex<SecretKey>(keyObj["private_key"].toString().toStdString());
        if (! decodeResult)
            return Error(E_FATAL, "Wallet", "Unable to read private key, it looks like your wallet data was corrupted");

        keyData.secretKey = *decodeResult;
        keyData.publicKey = derivePublicKey(keyData.secretKey);
        if (keyData.accountID != calcAccountID(keyData.publicKey))
            return Error(E_FATAL, "Wallet", "Private key doesn't match your account ID, it looks like your wallet data was corrupted");

        return noError;
    }
    else
    {
        // Encrypted wallet
        auto decodeResult2 = parseHex<std::vector<unsigned char> >(keyObj["encrypted_private_key"].toString().toStdString());
        auto decodeResult4 = parseHex<std::vector<unsigned char> >(keyObj["public_key"].toString().toStdString());

        if (! decodeResult2 || ! decodeResult4)
            return Error(E_FATAL, "Wallet", "Unable to decode encrypted key, it looks like your wallet data was corrupted");

        keyData.encryptedKey = *decodeResult2;
        keyData.publicKey = PublicKey(makeSlice(*decodeResult4));

        return noError;
    }
}

Error WalletMain::processWallet(const QJsonObject& keyObj)
{
    using namespace ripple;
    const auto& accs = keyObj["accounts"];
    int nSize = 0;

    if (!accs.isArray() || 0 == (nSize = accs.toArray().size()))
        return Error(E_FATAL, "Wallet", "Incorrect wallet JSON: unable to fetch accounts");

    for (const auto& account : accs.toArray())
    {
        KeyData keyData;
        auto res = processWalletEntry(account.toObject(), keyData);
        if (noError != res)
            return res;
        keyStore.push_back(keyData);
        accounts.push_back(toBase58(keyData.accountID).c_str());
    }

    balances = std::vector<int64_t>(nSize, 0);
    sequences = std::vector<int>(nSize, 0);
    transactions = std::vector<TxVector>(nSize, TxVector());

    return noError;
}

Error WalletMain::convertLegacyWallet(const QJsonObject& keyObj)
{
    using namespace ripple;

    if (keyObj["account_id"].isUndefined())
        return Error(E_FATAL, "Conversion", "Senseless wallet record found: no account ID");

    auto decodeResult1 = parseBase58<AccountID>(keyObj["account_id"].toString().toStdString());
    if (! decodeResult1)
        return Error(E_FATAL, "Conversion", "Unable to decode your account ID, it looks like your wallet data was corrupted.");

    if (keyObj["private_key"].isUndefined() && keyObj["encrypted_private_key"].isUndefined())
        return Error(E_FATAL, "Conversion", "Senseless wallet record found: no keys data for account " + keyObj["account_id"].toString());


    KeyData keyData;
    keyData.accountID = *decodeResult1;

    if (! keyObj["encrypted_private_key"].isUndefined())
    {
        // Encrypted wallet

        auto decodeResult2 = parseHex<std::vector<unsigned char> >(keyObj["salt"].toString().toStdString());
        if (! decodeResult2)
            return Error(E_FATAL, "Conversion", "Unable to decode encrypted wallet metadata");

        auto decodeResult3 = parseHex<std::vector<unsigned char> >(keyObj["encrypted_private_key"].toString().toStdString());
        if (! decodeResult3)
            return Error(E_FATAL, "Conversion", "Unable to decode encrypted key, it looks like your wallet data was corrupted");

        mSalt = *decodeResult2;
        keyData.encryptedKey = *decodeResult3;

        nDeriveIterations = keyObj["iterations"].toInt();
        if (nDeriveIterations == 0) nDeriveIterations = 500000;

        secure::string strPassword;

        while (true)
        {
            EnterPassword pwDialog(this);
            if (pwDialog.exec() != QDialog::Accepted)
                return noPassword; // User refused to enter the password
            bool fOk = true;
            strPassword = pwDialog.getPassword();
            if (fOk) fOk = legacyDecryptKey(keyData.encryptedKey, strPassword, mSalt, nDeriveIterations, keyData.secretKey);
            if (fOk) break;
            continue; // Wrong password, try again
        }

        keyData.publicKey = derivePublicKey(keyData.secretKey);
        if (keyData.accountID != calcAccountID(keyData.publicKey))
            return Error(E_FATAL, "Conversion", "Private key doesn't match your account ID, it looks like your wallet data was corrupted");

        secure::string rsaPrivKey;
        if (! generateRSAKeys(rsaPrivKey, mRSAPubKey))
            return Error(E_FATAL, "Conversion", "Unable to generate RSA key pair");

        if (! encryptRSAKey(rsaPrivKey, strPassword, mSalt, nDeriveIterations, mRSACryptedkey))
            return Error(E_FATAL, "Conversion", "Error while encrypting RSA private key");

        if (! encryptSecretKey(keyData.secretKey, mRSAPubKey, keyData.encryptedKey))
            return Error(E_FATAL, "Conversion", "Error while encrypting your wallet");
        keyData.secretKey.~SecretKey(); // Destroy secret key object
    }
    else
    {
        // Plain wallet
        auto decodeResult = parseHex<SecretKey>(keyObj["private_key"].toString().toStdString());
        if (! decodeResult)
            return Error(E_FATAL, "Conversion", "Unable to read private key, it looks like your wallet data was corrupted");
        keyData.secretKey = *decodeResult;
        keyData.publicKey = derivePublicKey(keyData.secretKey);
        if (keyData.accountID != calcAccountID(keyData.publicKey))
            return Error(E_FATAL, "Conversion", "Private key doesn't match your account ID, it looks like your wallet data was corrupted");
    }

    keyStore.push_back(keyData);
    accounts.push_back(toBase58(keyData.accountID).c_str());
    balances.push_back(0);
    sequences.push_back(0);
    transactions.push_back(TxVector());
    nCurrentAccount = 0;

    saveKeys();

    return noError;
}


Error WalletMain::loadWallet()
{
    using namespace ripple;

    QFile keyFile;
    keyFile.setFileName(QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + QDir::separator() + "keyStore.json");
    bool fOpened = keyFile.open(QIODevice::ReadOnly | QIODevice::Text);

    if (!fOpened)
    {
        // Brand new wallet
        ImportDialog importReq;
        QString strAccountID;
        while (true)
        {
            // Ask user to import his WIF formatted key
            if (importReq.exec() == QDialog::Accepted)
            {
                auto res = importKey(importReq.getKeyData(), strAccountID);
                if (noWif == res)
                    continue; // Incorrect WIF string entered, ask user again
                if( noError != res)
                    return res;
            }
            else
            {
                auto res = newKey(strAccountID); // User refused, generating new private key
                if (noError != res)
                    Show(res);
            }
            break;
        }

        return noError;
    }
    else
    {
        auto keyObj = QJsonDocument::fromJson(keyFile.readAll()).object();

        if (keyObj["encryption"].isObject())
        {
            // Encrypted wallet
            auto decodeResult1 = parseHex<std::vector<unsigned char> >(keyObj["encryption"].toObject()["salt"].toString().toStdString());
            auto decodeResult2 = parseHex<std::vector<unsigned char> >(keyObj["encryption"].toObject()["encrypted_master_private_key"].toString().toStdString());
            if (! decodeResult1 || ! decodeResult2)
                return Error(E_FATAL, "Wallet", "Unable to decode encrypted wallet metadata");

            mSalt = *decodeResult1;
            mRSACryptedkey = *decodeResult2;
            mRSAPubKey = keyObj["encryption"].toObject()["master_public_key"].toString().toStdString();
            nDeriveIterations = keyObj["encryption"].toObject()["iterations"].toInt();
            if (nDeriveIterations == 0) nDeriveIterations = 500000;

        }

        if (keyObj["main_account"].isDouble())
        {
            // Multi wallet mode
            nCurrentAccount = keyObj["main_account"].toDouble();
            return processWallet(keyObj);
        }
        else
        {
            // Convert single wallets
            return convertLegacyWallet(keyObj);
        }
    }

    return Error(E_FATAL, "Wallet", "Shouldn't happen in real life");
}

void WalletMain::saveKeys(bool fOverwrite)
{
    using namespace ripple;

    QJsonArray keysArr;
    for(const auto &keyData : keyStore)
    {
        QJsonObject keyObj;
        keyObj["account_id"] = toBase58(keyData.accountID).c_str();
        if (keyData.encryptedKey.size() != 0)
        {
            keyObj["encrypted_private_key"] = strHex(keyData.encryptedKey.data(), keyData.encryptedKey.size()).c_str();
            keyObj["public_key"] = strHex(keyData.publicKey.data(), keyData.publicKey.size()).c_str();
        }
        else
            keyObj["private_key"] = strHex(keyData.secretKey.data(), 32).c_str();

        keysArr.push_back(keyObj);
    }

    QJsonObject walletObj
    {
            { "main_account", nCurrentAccount },
            { "accounts", keysArr },
    };

    if (nDeriveIterations != 0)
    {
        walletObj["encryption"] = QJsonObject
        {
            { "master_public_key", mRSAPubKey.c_str() },
            { "encrypted_master_private_key", strHex(mRSACryptedkey.data(), mRSACryptedkey.size()).c_str() },
            { "salt", strHex(mSalt.data(), mSalt.size()).c_str() },
            { "iterations", nDeriveIterations }
        };
    }

    auto walletDoc = QJsonDocument (walletObj).toJson();

    QFile keyFile;
    keyFile.setFileName(QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + QDir::separator() + "keyStore.json");

    if (fOverwrite)
    {
        // Overwrite old file contents with zeros
        keyFile.open(QIODevice::WriteOnly | QIODevice::Text);
        QByteArray arrZeros(keyFile.size(), '0');
        keyFile.write(arrZeros, arrZeros.size());
        keyFile.flush();
        keyFile.close();
    }

    keyFile.open(QIODevice::WriteOnly | QIODevice::Text);
    keyFile.write(walletDoc, walletDoc.size());
    keyFile.close();
}

Error WalletMain::newKey(QString& newAccountID)
{
    using namespace ripple;
    KeyData keyData;
    std::tie(keyData.publicKey, keyData.secretKey) = randomKeyPair();
    keyData.accountID = calcAccountID(keyData.publicKey);

    if (nDeriveIterations != 0)
    {
        // Encrypt new key
        if (! encryptSecretKey(keyData.secretKey, mRSAPubKey, keyData.encryptedKey))
            return Error(E_FATAL, "New key", "Error while encrypting new key, operation has been aborted");
        keyData.secretKey.~SecretKey(); // Destroy secret key object
    }

    newAccountID = toBase58(keyData.accountID).c_str();

    keyStore.push_back(keyData);
    accounts.push_back(newAccountID);
    balances.push_back(0);
    sequences.push_back(0);
    transactions.push_back(TxVector());
    saveKeys();

    accInfoRequest({ newAccountID });
    accTxRequest({ newAccountID });
    subsLedgerAndAccountRequest();

    return noError;
}

Error WalletMain::importKey(const secure::string& keyString, QString& newAccountID)
{
    using namespace ripple;
    auto decodeResult = parseBase58<SecretKey>(TOKEN_ACCOUNT_WIF, keyString.c_str());
    if (! decodeResult)
        return noWif; // Incorrect WIF string
    KeyData keyData;
    keyData.secretKey = *decodeResult;
    keyData.publicKey = derivePublicKey(keyData.secretKey);
    keyData.accountID = calcAccountID(keyData.publicKey);
    newAccountID = toBase58(keyData.accountID).c_str();

    if (nDeriveIterations != 0)
    {
        // Encrypt new key
        if (! encryptSecretKey(keyData.secretKey, mRSAPubKey, keyData.encryptedKey))
            return Error(E_FATAL, "Key import", "Error while encrypting new key, operation has been aborted");
        keyData.secretKey.~SecretKey(); // Destroy secret key object
    }

    auto it = std::find(accounts.begin(), accounts.end(), newAccountID);
    if (it != accounts.end())
        return Error(E_WARN, "Key import", "This key already exists in your wallet");

    keyStore.push_back(keyData);
    accounts.push_back(newAccountID);
    balances.push_back(0);
    sequences.push_back(0);
    transactions.push_back(TxVector());
    saveKeys();

    accInfoRequest({ newAccountID });
    accTxRequest({ newAccountID });
    subsLedgerAndAccountRequest();

    return noError;
}

Error WalletMain::exportKey(QString& strKey)
{
    using namespace ripple;
    auto res = askPassword();
    if (noError == res)
        strKey = toWIF(keyStore[nCurrentAccount].secretKey).c_str();
    return res;
}


Error WalletMain::askPassword()
{
    using namespace ripple;
    auto& keyData = keyStore[nCurrentAccount];

    if (nDeriveIterations == 0)
        return noError;

    while (true)
    {
        EnterPassword pwDialog(this);
        if (pwDialog.exec() == QDialog::Accepted) {

            bool fOk = true;
            secure::string decryptionKey;
            fOk = decryptRSAKey(mRSACryptedkey, pwDialog.getPassword(), mSalt, nDeriveIterations, decryptionKey);
            if (fOk)
            {
                fOk = decryptSecretKey(keyData.encryptedKey, decryptionKey, keyData.secretKey);
                fOk = fOk && (keyData.accountID == calcAccountID(keyData.publicKey));
            }

            if (fOk) return noError;

            // Wrong password, try again
            continue;
        }
        else
        {
            // User refused to enter the password
            return noPassword;
        }
    }
}

WalletMain::WalletMain(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::WalletMain)
{

#ifdef QT_NO_SSL
#error "SSL support is required"
#endif

    auto res = loadWallet();
    if ( noError != res)
    {
        if (res != noPassword)
            Show(res);
        QTimer::singleShot(250, qApp, SLOT(quit()));
        return;
    }

    ui->setupUi(this);
    // Init in offline state
    setOnline(false, "Initialization is in progress");
    setupControls(parent);

    // Set message handlers
    connect(&m_webSocket, &QWebSocket::connected, this, &WalletMain::onConnected);
    connect(&m_webSocket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(onConnectionError(QAbstractSocket::SocketError)));

    //socketConnect();

    QTimer::singleShot(500, this, SLOT(doReconnect()));
}

void WalletMain::onConnectionError(QAbstractSocket::SocketError error)
{
    switch (error) {
    case QAbstractSocket::RemoteHostClosedError:
        setOnline(false, "Connection was closed by remote host.");
        break;
    case QAbstractSocket::HostNotFoundError:
        setOnline(false, "The host was not found. Please check your internet connection settings.");
        break;
    case QAbstractSocket::ConnectionRefusedError:
        setOnline(false, "The connection was refused by the peer. Please try again later. ");
        break;
    default:
        setOnline(false, QString("The following error occurred: %1.").arg(m_webSocket.errorString()));
    }

    if (nConnectAttempt <= 3)
        doReconnect();

    nConnectAttempt++;
}

void WalletMain::setOnline(bool flag, const QString& reason)
{
    using namespace ripple;

    QString strAccountID = toBase58(keyStore[nCurrentAccount].accountID).c_str();
    this->setWindowTitle(QString("RMC Wallet [%1%2]").arg(strAccountID).arg(flag ? "" : ", offline"));

    // Select default tab
    if (! flag) ui->tabWidget->setCurrentIndex(0);
    if (! flag) balances[nCurrentAccount] = 0;
    if (! flag) nLedger = -1;
    if (flag) nConnectAttempt = 0;

    // Send form and tab widget headers
    ui->sendButton->setEnabled(flag);
    ui->previewButton->setEnabled(flag);
    ui->tabWidget->setTabEnabled(1, flag);
    ui->tabWidget->setTabEnabled(2, flag);
    ui->sendTransactionFeeValue->setPlaceholderText(Amount(nFeeRef));

    // Statusbar labels
    balanceLabel.setText(QString("Balance: %1").arg(AmountWithSign(balances[nCurrentAccount])));
    ledgerLabel.setText(QString("Current ledger: %1").arg(nLedger));
    networkStatusLabel.setText(QString("Network status: %1").arg(reason));

    // Network info tab
    ui->latestLedgerHash->setText(ledgerHash);
    ui->latestLedgerNum->setText(QString("%1").arg(nLedger));
    ui->transactionsCount->setText(QString("%1").arg(ledgerTransactions));
    ui->closeTime->setText(timeFormat(ledgerCloseTime));
    ui->baseFeeValue->setText(AmountWithSign(nFee));
    ui->feeRefValue->setText(AmountWithSign(nFeeRef));
    ui->baseReserveValue->setText(AmountWithSign(nReserve));
}

void WalletMain::setupControls(QWidget *parent)
{
    // Setup amount validator
    std::unique_ptr<DoubleValidator> amountValidator(new DoubleValidator(parent));
    amountValidator->setDecimals(6);
    amountValidator->setBottom(0.00);
    amountValidator->setTop(10757.0);
    amountValidator->setNotation(QDoubleValidator::StandardNotation);
    ui->amountToSend->setValidator(amountValidator.get());
    ui->sendTransactionFeeValue->setValidator(amountValidator.get());

    // Setup tag validator
    std::unique_ptr<IntValidator> tagValidator(new IntValidator(parent));
    amountValidator->setBottom(0);
    ui->destinationTag->setValidator(tagValidator.get());

    // Hide columns
    ui->txView->setColumnHidden(4, true);
    // Set column sizes
    for(auto nCol : {0, 1, 3})
        ui->txView->setColumnWidth(nCol, 150);
    // Add statusBar labels
    for (auto pW : {&balanceLabel, &ledgerLabel, &networkStatusLabel})
        ui->statusBar->addWidget(pW);

    ui->txView->verticalHeader()->setVisible(false);
    ui->txView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->txView->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    ui->actionEncrypt_wallet->setDisabled(keyStore[nCurrentAccount].encryptedKey.size() != 0);

    connect(ui->txView, SIGNAL(cellDoubleClicked(int,int)), this, SLOT(txItemClicked(int,int)));
}

WalletMain::~WalletMain()
{
    delete ui;
}

bool WalletMain::isNetworkAvailable()
{
    // Trying connect to google.com
    QNetworkAccessManager nam;
    QNetworkRequest req(QUrl("http://google.com"));
    QNetworkReply *reply = nam.get(req);
    QEventLoop loop;
    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();
    return reply->bytesAvailable();
}

void WalletMain::socketConnect()
{
    using namespace std;

    if (! isNetworkAvailable()) {
        setOnline(false, "No internet connection");
        nConnectAttempt = 4;
        return;
    }

    // Connect to random RPC server
    vector<QString> servers = {"wss://connor.rmc.one:443/", "wss://kirk.rmc.one:443/", "wss://forrest.rmc.one:443/", "wss://archer.rmc.one:443/", "wss://lorca.rmc.one:443/"};
    random_device random_device;
    mt19937 engine{random_device()};
    uniform_int_distribution<int> dist(0, servers.size() - 1);
    m_webSocket.open(QUrl(servers[dist(engine)]));
}

void WalletMain::onConnected()
{
    connect(&m_webSocket, &QWebSocket::textMessageReceived,
            this, &WalletMain::onTextMessageReceived);
    accInfoRequest();
    accTxRequest();
    subsLedgerAndAccountRequest();
}

void WalletMain::doReconnect()
{
    setOnline(false, "Reconnecting");
    //reqMap.clear();
    if (m_webSocket.state() == QAbstractSocket::SocketState::ConnectedState)
        m_webSocket.close();
    socketConnect();
}

void WalletMain::onTextMessageReceived(QString message)
{
    auto msgDoc = QJsonDocument::fromJson(message.toUtf8());
    auto msgObj = msgDoc.object();

    // Check validity of received message
    if (!msgObj.contains("id") && !msgObj.contains("type"))
    {
        qDebug() << "Malformed JSON message received:" << message;
        return;
    }

    // Check whether this message is a response or notification
    if (msgObj.contains("id"))
    {
        // Exctract and check ID against the map of previously made requests
        int nMsgId = msgObj["id"].toInt();

        if (!msgObj["error"].isUndefined() && !msgObj["error"].isNull())
        {
            // QString errType = msgObj["error"].toString();
            // if (errType == "actNotFound") ...

            // TODO: Network error handling

            // Remove message ID from the map and return
            reqMap.erase(nMsgId);
            return;
        }

        if (msgObj["result"].isNull() || msgObj["result"].isUndefined())
        {
            qDebug() << "Something went wrong, NULL data received instead of proper response";

            // Remove message ID from the map and return
            reqMap.erase(nMsgId);
            return;
        }

        try
        {
            // Find message type
            auto msgKind = reqMap.at(nMsgId);

            // Remove message ID from the map
            reqMap.erase(nMsgId);

            switch(msgKind)
            {
            case MSG_ACCOUNT_INFO:
                return accInfoResponse(msgObj);
            case MSG_ACCOUNT_TX:
                return accTxResponse(msgObj);
            case MSG_SUBMIT_TX:
                return submitResponse(msgObj);
            case MSG_SUBSCRIBE_LEDGER_AND_ACCOUNT:
                return subsLedgerAndAccountResponse(msgObj);
            }
        }
        catch(std::out_of_range e)
        {
            qDebug() << "Unrequested message received: " << message;
        }
    }

    if (msgObj.contains("type"))
    {
        // New transaction accepted
        if (msgObj["type"] == "transaction")
            return processTxMessage(msgObj);

        // New ledger closed
        if (msgObj["type"] == "ledgerClosed")
            return processLedgerMessage(msgObj);
    }
}

void WalletMain::processTxMessage(QJsonObject txMsg)
{
    auto txMetaObj = txMsg["meta"].toObject();
    auto txObj = txMsg["transaction"].toObject();

    // Ignore unsuccessful transactions
    if (txMsg["engine_result"] != "tesSUCCESS")
        return accInfoRequest();

    // Parse transaction metadata
    if (txObj["TransactionType"] == "Payment" && !txObj["Amount"].isObject())
    {
        // Parse affected nodes list
        for (const auto& affRecord : txMetaObj["AffectedNodes"].toArray())
        {
            QJsonObject fieldsObj;

            // Check if our account was created just now
            if (affRecord.toObject()["CreatedNode"].isObject())
            {
                auto nodeObj = affRecord.toObject()["CreatedNode"].toObject();
                if (nodeObj["LedgerEntryType"] == "AccountRoot") {
                    fieldsObj = nodeObj["NewFields"].toObject();
                } else continue;
            }
            else
            {
                auto nodeObj = affRecord.toObject()["ModifiedNode"].toObject();
                if (nodeObj["LedgerEntryType"] == "AccountRoot") {
                    fieldsObj = nodeObj["FinalFields"].toObject();
                } else continue;
            }

            auto it = std::find(accounts.begin(), accounts.end(), fieldsObj["Account"]);
            if (it != accounts.end())
            {
                int nAccountIndex = std::distance(accounts.begin(), it);
                balances[nAccountIndex] = fieldsObj["Balance"].toString().toDouble();
                sequences[nAccountIndex] = fieldsObj["Sequence"].toDouble();
            }
        }

        auto it1 = std::find(accounts.begin(), accounts.end(), txObj["Account"]);
        auto it2 = std::find(accounts.begin(), accounts.end(), txObj["Destination"]);

        if (it1 != accounts.end())
        {
            // We are sender, add debit record
            int acc_idx = std::distance(accounts.begin(), it1);
            auto& rowData = transactions[acc_idx];
            rowData.insert(rowData.begin(), {
                timeFormat(txObj["date"].toInt()),
                txObj["TransactionType"].toString(),
                txObj["hash"].toString(),
                AmountWithSign(txObj["Amount"].toString().toDouble(), true),
                QJsonDocument(txObj).toJson()
            });

            if (nCurrentAccount == acc_idx)
                refreshTxView();
        }

        if (it2 != accounts.end())
        {
            // We are receiver, add credit record
            int acc_idx = std::distance(accounts.begin(), it2);
            auto& rowData = transactions[acc_idx];
            rowData.insert(rowData.begin(), {
                timeFormat(txObj["date"].toInt()),
                txObj["TransactionType"].toString(),
                txObj["hash"].toString(),
                AmountWithSign(txObj["Amount"].toString().toDouble()),
                QJsonDocument(txObj).toJson()
            });

            if (nCurrentAccount == acc_idx)
                refreshTxView();
        }

    }
    else
    {
        // No support for "complex" transactions yet, just ask to send us fresh transaction list
        accTxRequest();
    }

    // Update current ledger index
    ledgerLabel.setText("Current ledger: " + QString("%1").arg(txMsg["ledger_index"].toDouble()));
}

void WalletMain::processLedgerMessage(QJsonObject ledgerObj)
{
    nLedger = ledgerObj["ledger_index"].toDouble();
    nFee = ledgerObj["fee_base"].toDouble();
    nFeeRef = ledgerObj["fee_ref"].toDouble();
    nReserve = ledgerObj["reserve_base"].toDouble();
    ledgerHash = ledgerObj["ledger_hash"].toString();
    ledgerCloseTime = ledgerObj["ledger_time"].toDouble();
    ledgerTransactions = ledgerObj["txn_count"].toInt();
    setOnline(true, QString("ledger %1 closed").arg(ledgerHash.left(6)));
}

void WalletMain::accInfoResponse(QJsonObject obj)
{
    auto result = obj["result"].toObject();
    auto accountData = result["account_data"].toObject();

    auto it = std::find(accounts.begin(), accounts.end(), accountData["Account"]);
    if (it != accounts.end())
    {
        auto acc_idx = std::distance(accounts.begin(), it);
        sequences[acc_idx] = accountData["Sequence"].toDouble();
        balances[acc_idx] = accountData["Balance"].toString().toDouble();
    }

    setOnline(true, "Account info retrieved");
}

void WalletMain::accTxResponse(QJsonObject obj)
{
    QJsonObject result = obj["result"].toObject();
    QJsonArray txes = result["transactions"].toArray();

    // Get account ID as string.
    QString strAccountID = result["account"].toString();

    auto it = std::find(accounts.begin(), accounts.end(), strAccountID);
    auto acc_idx = std::distance(accounts.begin(), it);

    auto& rowData = transactions[acc_idx];
    rowData.clear();

    for (int i = 0; i < txes.size(); i++)
    {
        QJsonObject txObj = txes[i].toObject();
        if (!txObj["validated"].toBool())
            continue;
        if (txObj["meta"].toObject()["TransactionResult"].toString() != "tesSUCCESS")
            continue;

        txObj = txObj["tx"].toObject();

        bool isDebit = (txObj["Destination"].toString() != strAccountID);

        rowData.insert(rowData.end(), std::vector<QString> {
            timeFormat(txObj["date"].toDouble()),
            txObj["TransactionType"].toString(),
            txObj["hash"].toString(),
            AmountWithSign(txObj["Amount"].toString().toDouble(), isDebit),
            QJsonDocument(txObj).toJson()
        });
    }

    if (nCurrentAccount == acc_idx)
        refreshTxView();

    setOnline(true, "New transaction entry received");
}

void WalletMain::refreshTxView()
{
    const auto& rowData = transactions[nCurrentAccount];
    ui->txView->clearContents();
    ui->txView->setRowCount(rowData.size());

    for (auto nRow = 0u; nRow < rowData.size(); ++nRow)
    {
        for (auto nCol = 0u; nCol < rowData[nRow].size(); ++nCol)
        {
            QTableWidgetItem *newItem = new QTableWidgetItem();
            newItem->setText(rowData[nRow][nCol]);
            if (nCol == 5) newItem->setTextAlignment(Qt::AlignRight);
            ui->txView->setItem( nRow, nCol, newItem);
        }
    }
}

void WalletMain::submitResponse(QJsonObject obj)
{
    QJsonObject result = obj["result"].toObject();

    if (result["status"] == "error")
        Show("Transaction error", QString("Failure while committing transaction to the RMC network: ") + obj["error_message"].toString(), E_WARN);
    else if (result["engine_result"].toString() != "tesSUCCESS")
        Show("Transaction error", QString("Error while processing transaction by the RMC network: ") + result["engine_result_message"].toString(), E_WARN);
    else
        Show("Transaction applied", result["engine_result_message"].toString(), E_INFO);
}

void WalletMain::subsLedgerAndAccountResponse(QJsonObject obj)
{
    QJsonObject result = obj["result"].toObject();

    nFee = result["fee_base"].toDouble();
    nFeeRef = result["fee_ref"].toDouble();
    nLedger = result["ledger_index"].toDouble();
    nReserve = result["reserve_base"].toDouble();

    setOnline(true, "Subscribed to ledger and account notifications");
}

void WalletMain::accInfoRequest(QJsonArray accs)
{
    for (const auto& accountID : (accs.size() > 0 ? accs : accounts))
    {
        // Request account info
        reqMap[nRequestID] = MSG_ACCOUNT_INFO;
        m_webSocket.sendTextMessage(
           QJsonDocument(
           QJsonObject {
            {"id", nRequestID++},
            {"command", "account_info"},
            {"account",  accountID.toString() },
        }).toJson());
    }
}

void WalletMain::accTxRequest(QJsonArray accs)
{
    for (const auto& accountID : (accs.size() > 0 ? accs : accounts))
    {
        // Request account transactions
        reqMap[nRequestID] = MSG_ACCOUNT_TX;
        m_webSocket.sendTextMessage(
            QJsonDocument(
                QJsonObject {
                    {"id", nRequestID++},
                    {"command", "account_tx"},
                    {"account", accountID.toString() },
                    {"ledger_index_min", -1 },
                    {"ledger_index_max", -1 },
                    //{"limit", -1 },
                    {"forward", false },
                }).toJson());
    }
}

void WalletMain::submitRequest(QString hexBlobData)
{
    reqMap[nRequestID] = MSG_SUBMIT_TX;
    m_webSocket.sendTextMessage(
        QJsonDocument(
            QJsonObject {
                {"id", nRequestID++},
                {"command", "submit"},
                {"tx_blob", hexBlobData },
                {"fail_hard", true}
            }).toJson());
}

void WalletMain::subsLedgerAndAccountRequest()
{
    // Subscribe to ledger and account streams
    reqMap[nRequestID] = MSG_SUBSCRIBE_LEDGER_AND_ACCOUNT;
    m_webSocket.sendTextMessage(
        QJsonDocument(
            QJsonObject {
                {"id", nRequestID++},
                {"command", "subscribe"},
                {"accounts", accounts },
                {"streams", QJsonArray { "ledger" } },
        }).toJson());
}

void WalletMain::sendPayment(bool fJustAsk)
{
    auto& keyData = keyStore[nCurrentAccount];

    if (ui->receiverAddressEdit->text() == ripple::toBase58(keyData.accountID).c_str() )
        return Show("Error", "Sending to self basically has no sense and is not supported.", E_WARN);

    QString txHex, txJSON, strErr;
    QString strReceiver = ui->receiverAddressEdit->text();
    int64_t nAmount = readDouble(ui->amountToSend) * 1000000;
    int64_t nTagID = readInt(ui->destinationTag);
    int64_t nTxFee = readDouble(ui->sendTransactionFeeValue) * 1000000;
    if (nTxFee == 0) nTxFee = nFeeRef;

    if (nAmount > (balances[nCurrentAccount] - nTxFee - nReserve))
        return Show("Warning", "Transaction amount is greater than amount of available funds. This could happen if your available balance doesn't comply with either fee or reserve requirements.", E_WARN);

    auto result = createPaymentTx(strReceiver, nAmount, nTxFee, nTagID, txJSON, txHex);
    if (noError == result)
    {
        int expected = 0;
        QDialog* interaction = nullptr;

        if (fJustAsk)
        {
            QString strConf = "I'm about to send " + ui->amountToSend->text()
                    + " RMC to " + ui->receiverAddressEdit->text() + ". Do you agree?";

            expected = QMessageBox::Yes;
            interaction = new QMessageBox(QMessageBox::Information, "Confirmation", strConf, QMessageBox::Yes | QMessageBox::No);
        }
        else
        {
            expected = QDialog::Accepted;
            interaction = new TransactionPreview(nullptr, txJSON, txHex);
        }

        auto choice = interaction->exec();
        delete interaction;

        if (choice == expected)
        {
            // Submit transaction and disable send button till confirmation from server
            submitRequest(txHex);
            ui->sendButton->setEnabled(false);
            ui->previewButton->setEnabled(false);
            ui->receiverAddressEdit->setText("");
            ui->amountToSend->setText("");
            ui->destinationTag->setText("");
        }

        return;
    }

    if (result != noPassword)
        Show(result);
}

// Interface handlers

void WalletMain::txItemClicked(int nRow, int nCol)
{
    Q_UNUSED(nCol);

    QTableWidgetItem *item = new QTableWidgetItem;
    item = ui->txView->item(nRow, 4);
    TransactionView txDlg(nullptr, item->text());
    txDlg.exec();
}

void WalletMain::on_actionExit_triggered()
{
    qApp->quit();
}

void WalletMain::on_clearButton_clicked()
{
    ui->receiverAddressEdit->setText("");
    ui->amountToSend->setText("");
    ui->destinationTag->setText("");
}

void WalletMain::on_previewButton_clicked()
{
    sendPayment(false);
}

void WalletMain::on_sendButton_clicked()
{
    sendPayment(true);
}

void WalletMain::on_actionImport_key_triggered()
{
    ImportDialog importReq;
    importReq.hideNewKeyLabel();
    QString newAccountID;

    while (true)
    {
        // Ask user to import his WIF formatted key
        if (importReq.exec() != QDialog::Accepted)
            return; // User refused
        auto res = importKey(importReq.getKeyData(), newAccountID);
        if (noWif == res)
            continue; // Incorrect WIF string, ask user again
        if (noError != res)
            return Show(res);
    }

    Show("Import", QString("Key import was done successfully and account %1 has been created.").arg(newAccountID), E_INFO);
}

void WalletMain::on_actionGenerateNew_triggered()
{
    if (QMessageBox::Yes == QMessageBox(QMessageBox::Information, "Confirmation", "Are you sure you need another account?", QMessageBox::Yes|QMessageBox::No).exec())
    {
        QString newAccountID;
        auto res = newKey(newAccountID);
        if (noError != res)
            return Show(res);
        Show("Success", QString("Your new account %1 has been generated and saved successfully.").arg(newAccountID), E_INFO);
    }
}

void WalletMain::on_actionExport_key_triggered()
{
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->clear();
    QString keyWIF;
    auto res = exportKey(keyWIF);

    if (noError != res) {
        if (noPassword != res)
            Show(res);
        return;
    }

    keyStore[nCurrentAccount].secretKey.~SecretKey();
    clipboard->setText(keyWIF);
    Show("Export", "Your key is in clipboard now.", E_INFO);
}

void WalletMain::on_actionCopy_account_address_triggered()
{
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->clear();
    clipboard->setText(ripple::toBase58(keyStore[nCurrentAccount].accountID).c_str());
    Show("Copy account ID", "Your address is in clipboard now.", E_INFO);
}


void WalletMain::on_actionEncrypt_wallet_triggered()
{
    using namespace ripple;

    if (nDeriveIterations != 0) {
        return Show("Error", "Changing passphrase is not yet implemented.", E_FATAL);
    }

    EnterPassword pwDialog(this), pwDialogConf(this, true);

    if (pwDialog.exec() == QDialog::Accepted && pwDialogConf.exec() == QDialog::Accepted)
    {
        const auto& strPassword1 = pwDialog.getPassword();
        const auto& strPassword2 = pwDialogConf.getPassword();

        if (strPassword1 != strPassword2)
            return Show("Error", "Entered passwords do not match.", E_WARN);

        secure::string rsaPrivKey;
        if (! generateRSAKeys(rsaPrivKey, mRSAPubKey))
            return Show("Error", "Unable to generate RSA key pair", E_FATAL);

        if (! encryptRSAKey(rsaPrivKey, strPassword1, mSalt, nDeriveIterations, mRSACryptedkey))
            return Show("Error", "Error while encrypting RSA private key", E_FATAL);

        for(auto &keyData : keyStore)
        {
            if (keyData.encryptedKey.size() == 0)
            {
                if (! encryptSecretKey(keyData.secretKey, mRSAPubKey, keyData.encryptedKey))
                    return Show ("Error", "Error while encrypting your wallet", E_FATAL);
                keyData.secretKey.~SecretKey(); // Destroy secret key object
            }
        }

        saveKeys(true);
        Show("Information", "Your wallet file was successfully encrypted.", E_INFO);
    }
}

void WalletMain::on_actionReconnect_triggered()
{
    nConnectAttempt = 0;
    doReconnect();
}


void WalletMain::on_actionAbout_triggered()
{
    AboutDialog aboutDlg;
    aboutDlg.exec();
}


void WalletMain::on_actionSwitch_account_triggered()
{
    SwitchAccount accountDlg(NULL, accounts.toVariantList(), nCurrentAccount);
    if (accountDlg.exec() == QDialog::Accepted)
    {
       nCurrentAccount = accountDlg.getSelected();
       saveKeys();
       setOnline(true, "Account switched");
       refreshTxView();
       // doReconnect();

       //accInfoRequest();
       //accTxRequest();
    }
}

// Entry point

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    WalletMain w;
    w.show();

    return a.exec();
}


