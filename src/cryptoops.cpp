#include "../include/cryptoops.h"
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/hex.h>

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>

namespace CryptoOps {

// Defaults (overwritten by config.json)
static int AES_KEY_SIZE = 32;
static int HMAC_KEY_SIZE = 32;
static bool config_loaded = false;
static QString configPath = "../config.json";

bool loadConfig(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Could not open config file:" << path;
        return false;
    }

    QByteArray raw = file.readAll();
    file.close();

    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    if (doc.isNull()) {
        qWarning() << "Invalid JSON config:" << err.errorString();
        return false;
    }

    QJsonObject root = doc.object();
    if (root.contains("aes")) {
        QJsonObject aesObj = root["aes"].toObject();
        if (aesObj.contains("key_size"))
            AES_KEY_SIZE = aesObj["key_size"].toInt(32);
    }
    if (root.contains("hmac")) {
        QJsonObject hmacObj = root["hmac"].toObject();
        if (hmacObj.contains("key_size"))
            HMAC_KEY_SIZE = hmacObj["key_size"].toInt(32);
    }

    config_loaded = true;
    qDebug() << "Config loaded: AES_KEY_SIZE =" << AES_KEY_SIZE
             << ", HMAC_KEY_SIZE =" << HMAC_KEY_SIZE;
    return true;
}

QByteArray generateSymmetricKey()
{
    if (!config_loaded) loadConfig(configPath);

    CryptoPP::AutoSeededRandomPool rng;
    QByteArray key(AES_KEY_SIZE, 0);
    rng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(key.data()), key.size());
    return key;
}

QByteArray aesEncrypt(const QByteArray &data, const QByteArray &key)
{
    if (key.size() != AES_KEY_SIZE) {
        qWarning() << "AES encryption error: invalid key size";
        return QByteArray();
    }

    CryptoPP::AutoSeededRandomPool rng;
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

        cipher = QByteArray(reinterpret_cast<const char*>(iv.data()), iv.size());
        cipher.append(QByteArray::fromStdString(encrypted));
    }
    catch (const CryptoPP::Exception &e) {
        qWarning("AES encryption error: %s", e.what());
    }
    return cipher;
}

QByteArray aesDecrypt(const QByteArray &cipher, const QByteArray &key)
{
    if (cipher.size() < CryptoPP::AES::BLOCKSIZE || key.size() != AES_KEY_SIZE) {
        qWarning() << "AES decryption error: invalid input or key size";
        return QByteArray();
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

QString hmacDigest(const QByteArray &data, const QByteArray &key)
{
    if (!config_loaded) loadConfig(configPath);

    // if (key.size() != HMAC_KEY_SIZE) {
    //     qWarning() << "Invalid HMAC key size, expected" << HMAC_KEY_SIZE;
    //     return QString();
    // }

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

} 
