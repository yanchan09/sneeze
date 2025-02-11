#include <QApplication>

#include "ConnectWindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    ConnectWindow window;
    window.show();

    return app.exec();
}
