#pragma once

#include <QMainWindow>
#include <QPushButton>

class ConnectWindow : public QMainWindow {
    Q_OBJECT

private:
    QPushButton *submitButton;

public:
    explicit ConnectWindow(QWidget *parent = nullptr);

public Q_SLOTS:
    void onConnectClicked();
};
