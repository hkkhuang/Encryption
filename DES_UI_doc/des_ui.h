#ifndef DES_UI_H
#define DES_UI_H

#include <QWidget>
#include "DesCrypt.h"

namespace Ui {
class DES_UI;
}

class DES_UI : public QWidget
{
    Q_OBJECT //必须包含

public:
    explicit DES_UI(QWidget *parent = 0); //QWidget *parent = 0 表示DES_UI控件不是任何控件的子控件
    ~DES_UI();

private:
    Ui::DES_UI *ui;
    DesCrypt* Des = new DesCrypt();

//声明槽
private slots:
    void encrypt(); //加密处理函数
    void decrypt(); //解密处理函数

    //选择文件加解密
    int OnBtnOpenCLicked();
    int OnBtnSaveClicked();
};

#endif // DES_UI_H
