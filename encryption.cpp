#include "encryption.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#include <random>
#include <cassert>

bool generateRSAKeys(secure::string& psPrivKey, std::string& psPubKey)
{
     RSA *prKeyPair = RSA_new();
     BIGNUM *pbnExponent = BN_new();
     BN_set_word(pbnExponent, RSA_F4);

     int nRes = RSA_generate_key_ex (prKeyPair, 4096, pbnExponent, nullptr);

     if (nRes == 0)
     {
         RSA_free(prKeyPair);
         BN_clear_free(pbnExponent);
         CRYPTO_cleanup_all_ex_data();
         return false;
     }

     BIO *pri = BIO_new(BIO_s_mem());
     BIO *pub = BIO_new(BIO_s_mem());

     PEM_write_bio_RSAPrivateKey(pri, prKeyPair, nullptr, nullptr, 0, nullptr, nullptr);
     PEM_write_bio_RSAPublicKey(pub, prKeyPair);

     size_t nPriLen = BIO_pending(pri);
     size_t nPubLen = BIO_pending(pub);

     psPubKey.resize(nPubLen + 1);
     psPrivKey.resize(nPriLen + 1);
     std::fill(psPubKey.begin(), psPubKey.end(), 0);
     std::fill(psPrivKey.begin(), psPrivKey.end(), 0);

     BIO_read(pub, &psPubKey[0], nPubLen);
     BIO_read(pri, &psPrivKey[0], nPriLen);

     RSA_free(prKeyPair);
     BIO_free_all(pri);
     BIO_free_all(pub);
     BN_clear_free(pbnExponent);
     CRYPTO_cleanup_all_ex_data();

     return nRes != 0;
}

bool encryptRSAKey(const secure::string& psKeyData, const secure::string& psPassword, std::vector<unsigned char>& pvchSalt, int& pnDeriveIterations, std::vector<unsigned char>& pvchCryptedKey)
{
    pvchSalt.resize(8);
    if (! RAND_pseudo_bytes(&pvchSalt[0], pvchSalt.size()))
        return false;

    unsigned char chKey[32];
    unsigned char chIV[32];

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> uni(700000, 2000000);

    pnDeriveIterations = uni(rng);

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &pvchSalt[0], (const unsigned char *)&psPassword[0], psPassword.size(), pnDeriveIterations, chKey, chIV);

    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCK_SIZE - 1 bytes
    int nLen = psKeyData.size();
    int nCLen = nLen + AES_BLOCK_SIZE, nFLen = 0;
    pvchCryptedKey = std::vector<unsigned char> (nCLen);

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), nullptr, chKey, chIV) != 0;
    if (fOk) fOk = EVP_EncryptUpdate(&ctx, &pvchCryptedKey[0], &nCLen, (const unsigned char*)&psKeyData[0], nLen) != 0;
    if (fOk) fOk = EVP_EncryptFinal_ex(&ctx, &pvchCryptedKey[0] + nCLen, &nFLen) != 0;
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk) return false;

    pvchCryptedKey.resize(nCLen + nFLen);
    return true;
}

bool decryptRSAKey(const std::vector<unsigned char>& pvchCryptedKey, const secure::string& psPassword, const std::vector<unsigned char>& pvchSalt, int pnDeriveIterations, secure::string& psDecryptedKey)
{
    unsigned char chKey[32];
    unsigned char chIV[32];

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &pvchSalt[0],
            (const unsigned char *)&psPassword[0], psPassword.size(), pnDeriveIterations, chKey, chIV);

    // plaintext will always be equal to or lesser than length of ciphertext
    int nLen = pvchCryptedKey.size();
    int nPLen = nLen, nFLen = 0;

    psDecryptedKey.resize(nLen);

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), nullptr, chKey, chIV) != 0;
    if (fOk) fOk = EVP_DecryptUpdate(&ctx, (unsigned char*)&psDecryptedKey[0], &nPLen, &pvchCryptedKey[0], nLen) != 0;
    if (fOk) fOk = EVP_DecryptFinal_ex(&ctx, (unsigned char*)&psDecryptedKey[0] + nPLen, &nFLen) != 0;
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk) return false;

    psDecryptedKey.resize(nPLen + nFLen);

    return true;
}

bool legacyDecryptKey(const std::vector<unsigned char>& pvchCryptedKey, const secure::string& psPassword, const std::vector<unsigned char>& pvchSalt, int pnDeriveIterations, ripple::SecretKey& prsSecret)
{
    using namespace ripple;

    unsigned char chKey[32];
    unsigned char chIV[32];

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &pvchSalt[0],
            (const unsigned char *)&psPassword[0], psPassword.size(), pnDeriveIterations, chKey, chIV);

    // plaintext will always be equal to or lesser than length of ciphertext
    int nLen = pvchCryptedKey.size();
    int nPLen = nLen, nFLen = 0;

    secure::secret decryptedKey;
    decryptedKey.resize(nLen);

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), nullptr, chKey, chIV) != 0;
    if (fOk) fOk = EVP_DecryptUpdate(&ctx, &decryptedKey[0], &nPLen, &pvchCryptedKey[0], nLen) != 0;
    if (fOk) fOk = EVP_DecryptFinal_ex(&ctx, &decryptedKey[0] + nPLen, &nFLen) != 0;
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk) return false;

    decryptedKey.resize(nPLen + nFLen);
    prsSecret = SecretKey(Slice(decryptedKey.data(), decryptedKey.size()));

    return true;
}

//// Asymmetric encryption

bool encryptSecretKey(const ripple::SecretKey& prsSecret, const std::string& psEncryptionKey, std::vector<unsigned char>& pvchEncryptedKey)
{
    BIO* bio = BIO_new_mem_buf((const void*)&psEncryptionKey[0], -1) ; // -1: assume string is null terminated
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL) ; // NO NL
    // Load the RSA key from the BIO
    RSA* rsa_pub_key = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
    if(!rsa_pub_key)
    {
        BIO_free(bio);
        CRYPTO_cleanup_all_ex_data();
        return false;
    }

    pvchEncryptedKey.resize(RSA_size(rsa_pub_key));
    std::fill(pvchEncryptedKey.begin(), pvchEncryptedKey.end(), 0);
    std::vector<unsigned char> vguard(pvchEncryptedKey.size(), 0);

    int nRes = RSA_public_encrypt(prsSecret.size(), prsSecret.data(), &pvchEncryptedKey[0], rsa_pub_key, RSA_PKCS1_PADDING);
    assert(vguard != pvchEncryptedKey);

    BIO_free(bio);
    CRYPTO_cleanup_all_ex_data();

    return (nRes > 0) && (nRes == RSA_size(rsa_pub_key));
}

bool decryptSecretKey(const std::vector<unsigned char>& pvchEncryptedSecret, const secure::string& psDecryptionKey, ripple::SecretKey& prsSecretKey)
{
    using namespace ripple;

    BIO *bio = BIO_new_mem_buf( (const void*)&psDecryptionKey[0], -1 );
    //BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // NO NL
    RSA* rsa_priv_key = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    if (!rsa_priv_key)
    {
        BIO_free( bio ) ;
        CRYPTO_cleanup_all_ex_data();
        return false;
    }

    int nRsaLen = RSA_size(rsa_priv_key);
    secure::secret secretData;
    secretData.resize(nRsaLen);
    std::fill(secretData.begin(), secretData.end(), 0);

    int nResLen = RSA_private_decrypt(secretData.size(), &pvchEncryptedSecret[0], &secretData[0], rsa_priv_key, RSA_PKCS1_PADDING);

    BIO_free( bio ) ;
    CRYPTO_cleanup_all_ex_data();

    if (nResLen < 0)
        return false;

    prsSecretKey = SecretKey(Slice(&secretData[0], nResLen));

    return true;
}
