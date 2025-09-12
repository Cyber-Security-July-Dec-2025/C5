#include "../include/mainwindow.h"
#include "ui_mainwindow.h"
#include "../include/cryptoops.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QByteArray>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);


    connect(ui->uploadButton,   &QPushButton::clicked, this, &MainWindow::onUploadClicked);
    connect(ui->processButton,  &QPushButton::clicked, this, &MainWindow::onProcessClicked);
    connect(ui->downloadButton, &QPushButton::clicked, this, &MainWindow::onDownloadClicked);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::onUploadClicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, "Select File");
    if (fileName.isEmpty())
        return;

    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "Error", "Unable to open file.");
        return;
    }

    originalData = file.readAll();
    file.close();

    ui->inputPathEdit->setText(fileName);
    ui->statusLabel->setText("Status: File uploaded");
}

static QByteArray fromHexString(const QString &hex)
{
    QByteArray raw = QByteArray::fromHex(hex.toUtf8());
    return raw;
}

void MainWindow::onProcessClicked()
{
    QString op = ui->operationCombo->currentText();
    ui->progressBar->setValue(0);
    ui->outputText->clear();

    if (op == "Generate Symmetric Key") {
        key = CryptoOps::generateSymmetricKey();
        ui->keyHexEdit->setText(key.toHex());
        ui->outputText->setPlainText("Generated Key (hex): " + key.toHex());
    }
    else if (op == "AES Encrypt (CBC)") {
        if (originalData.isEmpty()) {
            QMessageBox::warning(this, "Error", "No input file loaded.");
            return;
        }

        QByteArray useKey = fromHexString(ui->keyHexEdit->text());
        if (useKey.isEmpty())
            useKey = CryptoOps::generateSymmetricKey();

        key = useKey;
        processedData = CryptoOps::aesEncrypt(originalData, key);

        ui->outputText->setPlainText("Encrypted Data (hex):\n" + processedData.toHex());
    }
    else if (op == "AES Decrypt (CBC)") {
        if (originalData.isEmpty()) {
            QMessageBox::warning(this, "Error", "No input file loaded.");
            return;
        }

        QByteArray useKey = fromHexString(ui->keyHexEdit->text());
        if (useKey.isEmpty()) {
            QMessageBox::warning(this, "Error", "AES key required for decryption.");
            return;
        }

        key = useKey;
        processedData = CryptoOps::aesDecrypt(originalData, key);

        ui->outputText->setPlainText("Decrypted Data (UTF-8):\n" + QString::fromUtf8(processedData));
    }
    else if (op == "SHA-256") {
        if (originalData.isEmpty()) {
            QMessageBox::warning(this, "Error", "No input file loaded.");
            return;
        }

        QString digest = CryptoOps::sha256Digest(originalData);
        ui->outputText->setPlainText("SHA-256 Digest:\n" + digest);
    }
    else if (op == "HMAC-SHA256") {
        if (originalData.isEmpty()) {
            QMessageBox::warning(this, "Error", "No input file loaded.");
            return;
        }

        QByteArray useKey = fromHexString(ui->hmacKeyHexEdit->text());
        if (useKey.isEmpty()) {
            QMessageBox::warning(this, "Error", "HMAC key required.");
            return;
        }

        QString digest = CryptoOps::hmacDigest(originalData, useKey);
        ui->outputText->setPlainText("HMAC-SHA256 Digest:\n" + digest);
    }

    ui->statusLabel->setText("Status: Operation completed");
    ui->progressBar->setValue(100);
}

void MainWindow::onDownloadClicked()
{
    if (processedData.isEmpty()) {
        QMessageBox::warning(this, "Error", "No processed data available.");
        return;
    }

    QString saveName = QFileDialog::getSaveFileName(this, "Save Output File");
    if (saveName.isEmpty())
        return;

    QFile file(saveName);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, "Error", "Unable to save file.");
        return;
    }

    file.write(processedData);
    file.close();

    ui->statusLabel->setText("Status: Output saved");
}
