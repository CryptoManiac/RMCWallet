#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>
#include <openssl/crypto.h>
#include <ripple/protocol/SecretKey.h>

#include "secure.h"

class key_error : public std::runtime_error
{
public:
    explicit key_error(const std::string& str) : std::runtime_error(str) {}
};

// Generate new RSA key pair
bool generateRSAKeys(secure::string& psPrivKey, std::string& psPubKey);

// Encrypt RSA private key with password derived AES key
bool encryptRSAKey(const secure::string& psKeyData, const secure::string& psPassword, std::vector<unsigned char>& pvchSalt, int& pnDeriveIterations, std::vector<unsigned char>& pvchCryptedKey);

// Decrypt RSA private key using password derived AES key
bool decryptRSAKey(const std::vector<unsigned char>& pvchCryptedKey, const secure::string& psPassword, const std::vector<unsigned char>& pvchSalt, int pnDeriveIterations, secure::string& psDecryptedKey);

// Decrypt AES encrypted keys
bool legacyDecryptKey(const std::vector<unsigned char>& pvchCryptedKey, const secure::string& psPassword, const std::vector<unsigned char>& pvchSalt, int pnDeriveIterations, ripple::SecretKey& prsSecret);

// Encrypt secp256k1 key using RSA public key
bool encryptSecretKey(const ripple::SecretKey& prsSecret, const std::string& psEncryptionKey, std::vector<unsigned char>& pvchEncryptedKey);

// Decrypt secp256k1 key using RSA private key
bool decryptSecretKey(const std::vector<unsigned char>& pvchEncryptedSecret, const secure::string& psDecryptionKey, ripple::SecretKey& prsSecretKey);

#endif // ENCRYPTION_H
