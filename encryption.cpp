#include "encryption.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

bool encryptKey(const ripple::SecretKey& keyData, const std::string& strPassword, std::vector<unsigned char>& salt, int& nDeriveIterations, std::vector<unsigned char>& cryptedKey)
{
    salt.resize(8);
    if (! RAND_pseudo_bytes(&salt[0], salt.size()))
        return false;

    unsigned char chKey[32];
    unsigned char chIV[32];

    uint32_t nMin = 500000, nMax = 10000000;
    uint32_t nRange = (std::numeric_limits<uint32_t>::max() / nMax) * nMax;
    uint32_t nRand = 0;
    do {
        RAND_bytes((unsigned char*)&nRand, sizeof(nRand));
    } while (nRand >= nRange && (nRand % nMax) < nMin);
    nDeriveIterations = (nRand % nMax);

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &salt[0],
    (unsigned char *)&strPassword[0], strPassword.size(), nDeriveIterations, chKey, chIV);

    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCK_SIZE - 1 bytes
    int nLen = keyData.size();
    int nCLen = nLen + AES_BLOCK_SIZE, nFLen = 0;
    cryptedKey = std::vector<unsigned char> (nCLen);

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, chKey, chIV) != 0;
    if (fOk) fOk = EVP_EncryptUpdate(&ctx, &cryptedKey[0], &nCLen, keyData.data(), nLen) != 0;
    if (fOk) fOk = EVP_EncryptFinal_ex(&ctx, (&cryptedKey[0]) + nCLen, &nFLen) != 0;
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk) return false;

    cryptedKey.resize(nCLen + nFLen);
    return true;
}

bool decryptKey(const std::vector<unsigned char>& cryptedKey, const std::string& strPassword, const std::vector<unsigned char>& salt, int nDeriveIterations, ripple::SecretKey& decryptedKey)
{
    unsigned char chKey[32];
    unsigned char chIV[32];

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &salt[0],
            (unsigned char *)&strPassword[0], strPassword.size(), nDeriveIterations, chKey, chIV);

    // plaintext will always be equal to or lesser than length of ciphertext
    int nLen = cryptedKey.size();
    int nPLen = nLen, nFLen = 0;

    decryptedKey = ripple::SecretKey();

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, chKey, chIV) != 0;
    if (fOk) fOk = EVP_DecryptUpdate(&ctx, decryptedKey.data(), &nPLen, &cryptedKey[0], nLen) != 0;
    if (fOk) fOk = EVP_DecryptFinal_ex(&ctx, decryptedKey.data() + nPLen, &nFLen) != 0;
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk) return false;

    return true;
}
