#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QByteArray>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onUploadClicked();
    void onProcessClicked();
    void onDownloadClicked();

private:
    Ui::MainWindow *ui;

    QByteArray originalData;
    QByteArray processedData;
    QByteArray key;
};

#endif // MAINWINDOW_H
