#include "../include/cryptoops.h"

#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/hex.h>

namespace CryptoOps {

// Generate a 256-bit (32-byte) symmetric key
QByteArray generateSymmetricKey()
{
    CryptoPP::AutoSeededRandomPool rng;
    QByteArray key(32, 0); // 256-bit
    rng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(key.data()), key.size());
    return key;
}

// AES-256 encryption (CBC mode, with random IV prepended to ciphertext)
QByteArray aesEncrypt(const QByteArray &data, const QByteArray &key)
{
    CryptoPP::AutoSeededRandomPool rng;

    // IV must be AES::BLOCKSIZE (16 bytes)
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    rng.GenerateBlock(iv, iv.size());

    QByteArray cipher;
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor(
            reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size(), iv);

        std::string encrypted;
        CryptoPP::StringSource ss(
            std::string(data.constData(), data.size()), true,
            new CryptoPP::StreamTransformationFilter(
                encryptor,
                new CryptoPP::StringSink(encrypted)
            )
        );

        // Prepend IV to ciphertext
        cipher = QByteArray(reinterpret_cast<const char*>(iv.data()), iv.size());
        cipher.append(QByteArray::fromStdString(encrypted));
    }
    catch (const CryptoPP::Exception &e) {
        qWarning("AES encryption error: %s", e.what());
    }

    return cipher;
}

// AES-256 decryption (expects IV prepended to ciphertext)
QByteArray aesDecrypt(const QByteArray &cipher, const QByteArray &key)
{
    if (cipher.size() < CryptoPP::AES::BLOCKSIZE) {
        return QByteArray(); // too short
    }

    QByteArray ivBytes = cipher.left(CryptoPP::AES::BLOCKSIZE);
    QByteArray encrypted = cipher.mid(CryptoPP::AES::BLOCKSIZE);

    QByteArray plain;
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor(
            reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size(),
            reinterpret_cast<const CryptoPP::byte*>(ivBytes.data())
        );

        std::string decrypted;
        CryptoPP::StringSource ss(
            std::string(encrypted.constData(), encrypted.size()), true,
            new CryptoPP::StreamTransformationFilter(
                decryptor,
                new CryptoPP::StringSink(decrypted)
            )
        );

        plain = QByteArray::fromStdString(decrypted);
    }
    catch (const CryptoPP::Exception &e) {
        qWarning("AES decryption error: %s", e.what());
    }

    return plain;
}

// SHA-256 digest (hex string)
QString sha256Digest(const QByteArray &data)
{
    std::string digest;
    try {
        CryptoPP::SHA256 hash;
        CryptoPP::StringSource ss(
            std::string(data.constData(), data.size()), true,
            new CryptoPP::HashFilter(hash,
                new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false)
            )
        );
    }
    catch (const CryptoPP::Exception &e) {
        qWarning("SHA256 error: %s", e.what());
    }

    return QString::fromStdString(digest);
}

// HMAC-SHA256 (hex string)
QString hmacDigest(const QByteArray &data, const QByteArray &key)
{
    std::string mac;
    try {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(
            reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());

        CryptoPP::StringSource ss(
            std::string(data.constData(), data.size()), true,
            new CryptoPP::HashFilter(hmac,
                new CryptoPP::HexEncoder(new CryptoPP::StringSink(mac), false)
            )
        );
    }
    catch (const CryptoPP::Exception &e) {
        qWarning("HMAC error: %s", e.what());
    }

    return QString::fromStdString(mac);
}

} // namespace CryptoOps
