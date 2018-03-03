#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>

#include <ripple/protocol/SecretKey.h>

bool encryptKey(const ripple::SecretKey& keyData, const std::string& strPassword, std::vector<unsigned char>& salt, int& nDeriveIterations, std::vector<unsigned char>& cryptedKey);
bool decryptKey(const std::vector<unsigned char>& cryptedKey, const std::string& strPassword, const std::vector<unsigned char>& salt, int nDeriveIterations, ripple::SecretKey& decryptedKey);


#endif // ENCRYPTION_H
