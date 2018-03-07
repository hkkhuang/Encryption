#include "des_ui.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    DES_UI w; //创建界面对象
    w.show(); //显示界面

    return a.exec();
}
