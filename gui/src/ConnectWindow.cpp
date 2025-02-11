#include <QWidget>
#include <QMainWindow>
#include <QFormLayout>
#include <QLineEdit>

#include <stdio.h>

#include "ConnectWindow.h"
#include "qboxlayout.h"
#include "qpushbutton.h"
#include "qwidget.h"

ConnectWindow::ConnectWindow(QWidget *parent) : QMainWindow(parent) {
    QLineEdit *serverLineEdit = new QLineEdit;
    QLineEdit *roomLineEdit = new QLineEdit;
    QLineEdit *nicknameLineEdit = new QLineEdit;

    serverLineEdit->setText("127.0.0.1:8443");
    roomLineEdit->setText("test");
    nicknameLineEdit->setText("tester");

    QWidget *centralWidget = new QWidget;
    QVBoxLayout *centralLayout = new QVBoxLayout(centralWidget);

    QWidget *formWidget = new QWidget;
    QFormLayout *layout = new QFormLayout(formWidget);
    layout->addRow("&Server", serverLineEdit);
    layout->addRow("&Room", roomLineEdit);
    layout->addRow("&Nickname", nicknameLineEdit);

    centralLayout->addWidget(formWidget);

    submitButton = new QPushButton("&Connect");
    submitButton->connect(submitButton, &QPushButton::clicked, this, &ConnectWindow::onConnectClicked);
    centralLayout->addWidget(submitButton);

    setCentralWidget(centralWidget);
}

void ConnectWindow::onConnectClicked() {
    printf("Connect clicked!\n");
    submitButton->setDisabled(true);
}
