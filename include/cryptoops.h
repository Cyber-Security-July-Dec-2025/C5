#pragma once
#include <QString>
#include <QByteArray>

namespace CryptoOps {

bool loadConfig(const QString &path);

QByteArray generateSymmetricKey();
QByteArray aesEncrypt(const QByteArray &data, const QByteArray &key);
QByteArray aesDecrypt(const QByteArray &cipher, const QByteArray &key);
QString sha256Digest(const QByteArray &data);
QString hmacDigest(const QByteArray &data, const QByteArray &key);

}
