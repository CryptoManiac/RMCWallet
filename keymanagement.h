#ifndef KEYMANAGEMENT_H
#define KEYMANAGEMENT_H

#include <ripple/protocol/PublicKey.h>
#include <ripple/protocol/SecretKey.h>

struct KeyData {
    ripple::SecretKey rsSecretKey;
    ripple::PublicKey rpPublicKey;
    std::vector<unsigned char> vchCryptedKey;
    ripple::AccountID raAccountID;
};

class CKeyManagement
{
public:
    CKeyManagement();
};

#endif // KEYMANAGEMENT_H
