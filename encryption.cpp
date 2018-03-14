#include "encryption.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <random>

bool generateRSAKeys(secure::string& strPrivKey, std::string& strPubKey)
{
     RSA *kp = RSA_new();
     BIGNUM *exponent = BN_new();
     BN_set_word(exponent, RSA_F4);

     int res = RSA_generate_key_ex (kp, 4096, exponent, NULL);

     if (res == 0)
     {
         RSA_free(kp);
         BN_clear_free(exponent);
         CRYPTO_cleanup_all_ex_data();
         return false;
     }

     BIO *pri = BIO_new(BIO_s_mem());
     BIO *pub = BIO_new(BIO_s_mem());

     PEM_write_bio_RSAPrivateKey(pri, kp, NULL, NULL, 0, NULL, NULL);
     PEM_write_bio_RSAPublicKey(pub, kp);

     size_t pri_len = BIO_pending(pri);
     size_t pub_len = BIO_pending(pub);

     strPubKey.resize(pub_len + 1);
     strPrivKey.resize(pri_len + 1);
     std::fill(strPubKey.begin(), strPubKey.end(), 0);
     std::fill(strPrivKey.begin(), strPrivKey.end(), 0);

     BIO_read(pub, &strPubKey[0], pub_len);
     BIO_read(pri, &strPrivKey[0], pri_len);

     RSA_free(kp);
     BIO_free_all(pri);
     BIO_free_all(pub);
     BN_clear_free(exponent);
     CRYPTO_cleanup_all_ex_data();

     return res != 0;
}

bool encryptRSAKey(const secure::string& keyData, const secure::string& strPassword, std::vector<unsigned char>& salt, int& nDeriveIterations, std::vector<unsigned char>& cryptedKey)
{
    salt.resize(8);
    if (! RAND_pseudo_bytes(&salt[0], salt.size()))
        return false;

    unsigned char chKey[32];
    unsigned char chIV[32];

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> uni(700000, 2000000);

    nDeriveIterations = uni(rng);

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &salt[0], (const unsigned char *)&strPassword[0], strPassword.size(), nDeriveIterations, chKey, chIV);

    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCK_SIZE - 1 bytes
    int nLen = keyData.size();
    int nCLen = nLen + AES_BLOCK_SIZE, nFLen = 0;
    cryptedKey = std::vector<unsigned char> (nCLen);

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), nullptr, chKey, chIV) != 0;
    if (fOk) fOk = EVP_EncryptUpdate(&ctx, (unsigned char*)&cryptedKey[0], &nCLen, (unsigned char*)&keyData[0], nLen) != 0;
    if (fOk) fOk = EVP_EncryptFinal_ex(&ctx, ((unsigned char*)&cryptedKey[0]) + nCLen, &nFLen) != 0;
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk) return false;

    cryptedKey.resize(nCLen + nFLen);
    return true;
}

bool decryptRSAKey(const std::vector<unsigned char>& cryptedKey, const secure::string& strPassword, const std::vector<unsigned char>& salt, int nDeriveIterations, secure::string& decryptedKey)
{
    unsigned char chKey[32];
    unsigned char chIV[32];

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &salt[0],
            (const unsigned char *)&strPassword[0], strPassword.size(), nDeriveIterations, chKey, chIV);

    // plaintext will always be equal to or lesser than length of ciphertext
    int nLen = cryptedKey.size();
    int nPLen = nLen, nFLen = 0;

    decryptedKey.resize(nLen);

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), nullptr, chKey, chIV) != 0;
    if (fOk) fOk = EVP_DecryptUpdate(&ctx, (unsigned char*)&decryptedKey[0], &nPLen, &cryptedKey[0], nLen) != 0;
    if (fOk) fOk = EVP_DecryptFinal_ex(&ctx, (unsigned char*)&decryptedKey[0] + nPLen, &nFLen) != 0;
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk) return false;

    decryptedKey.resize(nPLen + nFLen);

    return true;
}

//// Asymmetric encryption

bool encryptSecretKey(const ripple::SecretKey& secret, const std::string& encryptionKey, std::vector<unsigned char>& encrypted)
{
    BIO* bio = BIO_new_mem_buf((void*)&encryptionKey[0], -1) ; // -1: assume string is null terminated
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL) ; // NO NL
    // Load the RSA key from the BIO
    RSA* rsa_pub_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    if(!rsa_pub_key)
    {
        BIO_free(bio);
        CRYPTO_cleanup_all_ex_data();
        return false;
    }

    encrypted.resize(RSA_size(rsa_pub_key));
    std::fill(encrypted.begin(), encrypted.end(), 0);

    int res = RSA_public_encrypt(secret.size(), secret.data(), &encrypted[0], rsa_pub_key, RSA_PKCS1_PADDING);

    BIO_free(bio);
    CRYPTO_cleanup_all_ex_data();

    return res > 0;
}

bool decryptSecretKey(const std::vector<unsigned char>& encryptedSecret, const secure::string& decryptionKey, ripple::SecretKey& secretKey)
{
    using namespace ripple;

    BIO *bio = BIO_new_mem_buf( (void*)&decryptionKey[0], -1 );
    //BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // NO NL
    RSA* rsa_priv_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (!rsa_priv_key)
    {
        BIO_free( bio ) ;
        CRYPTO_cleanup_all_ex_data();
        return false;
    }

    int rsa_len = RSA_size(rsa_priv_key);
    secure::secret secretData;
    secretData.resize(rsa_len);
    std::fill(secretData.begin(), secretData.end(), 0);

    int res_len = RSA_private_decrypt(secretData.size(), &encryptedSecret[0], &secretData[0], rsa_priv_key, RSA_PKCS1_PADDING);

    BIO_free( bio ) ;
    CRYPTO_cleanup_all_ex_data();

    if (res_len < 0)
        return false;

    secretKey = SecretKey(Slice(&secretData[0], res_len));

    return true;
}
