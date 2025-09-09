#include "../include/mainwindow.h"
#include "ui_mainwindow.h"
#include "../include/cryptoops.h"
#include <QFileDialog>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // Connect buttons to slots
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
    // TODO: implement file picker
}

void MainWindow::onProcessClicked()
{
    // TODO: call cryptographic functions from cryptoops.cpp
}

void MainWindow::onDownloadClicked()
{
    // TODO: save processed file
}
