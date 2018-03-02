#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>

bool encryptKey(const std::vector<unsigned char>& keyData, const std::string& strPassword, std::vector<unsigned char>& salt, std::vector<unsigned char>& cryptedKey);
bool decryptKey(const std::vector<unsigned char>& cryptedKey, const std::string& strPassword, const std::vector<unsigned char>& salt, std::vector<unsigned char>& decryptedKey);


#endif // ENCRYPTION_H
