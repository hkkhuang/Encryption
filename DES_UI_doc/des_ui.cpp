#include "DES_UI.h"
#include "ui_DES_UI.h"
#include <QFileDialog>
#include "GBK.h"
#include <QDebug>
#include <QFile>

DES_UI::DES_UI(QWidget *parent) : QWidget(parent), ui(new Ui::DES_UI)
{
    ui->setupUi(this);
    //设置默认初识值
    QString str = "12345678";
    ui->keyline->setText(str);
    str = "huangkeke";
    ui->en_Text->setPlainText(str);
    //str = "cipher:163a9d27f4e92b82e128e58ef5753cfb\ndata:huangkeke";
    //ui->plainTextEdit->setPlainText(str);
    //建立连接
    connect(ui->en_Button,SIGNAL(clicked()),this,SLOT(encrypt()));
    connect(ui->de_Button,SIGNAL(clicked()),this,SLOT(decrypt()));

    //添加连接
    connect(ui->btnOpen, SIGNAL(clicked()), this, SLOT(OnBtnOpenCLicked()));
    connect(ui->btnSave, SIGNAL(clicked()), this, SLOT(OnBtnSaveClicked()));
}

DES_UI::~DES_UI()
{
    delete ui;
    delete Des;
}

//加密处理函数
void DES_UI::encrypt()
{
    QString Qkey = ui->keyline->text();
    QString data = ui->en_Text->toPlainText();
    ui->de_Text->clear();
    QString err = "InputError,please check your input!";
    if(Qkey.isEmpty()||data.isEmpty()){
        ui->de_Text->setPlainText(err);
        return;
    }
    if(Qkey.length()!=8){
        ui->de_Text->setPlainText("length of key must be 8!");
        return;
    }

    char *key = Qkey.toLatin1().data();
    Des->setKey(key);
    Des->encrypt(data.toLatin1().data());
    QString endata = QString::fromLocal8Bit(Des->endata.c_str());
    ui->de_Text->setPlainText(endata);
}

//解密处理函数
void DES_UI::decrypt()
{
    QString Qkey = ui->keyline->text();
    QString data = ui->de_Text->toPlainText();
    ui->en_Text->clear();
    QString err = "InputError,please check your input!";
    if(Qkey.isEmpty()||data.isEmpty()){
        ui->en_Text->setPlainText(err);
        return;
    }
    if(Qkey.length()!=8){
        ui->de_Text->setPlainText("length of key must be 8!");
        return;
    }

    char *key = Qkey.toLatin1().data();
    Des->setKey(key);
    Des->decrypt(data.toLatin1().data());
    QString dedata = QString::fromLocal8Bit(Des->dedata.c_str());
    ui->en_Text->setPlainText(dedata);
}


int DES_UI::OnBtnOpenCLicked()
{
    //选择要打开的文件
    QString filepath = QFileDialog::getOpenFileName(
        this,//父窗口
        GBK::ToUnicode("选择文件") //标题Caption
    );

    //为空时表示用户取消了操作,没有选择文件
    if (filepath.length()>0)
    {
        qDebug() << filepath;  //"输出"信息中查看文件路径信息
        string gbk_name = GBK::FromUnicode(filepath);// 将读取的文件路径,转换为GBK形式

        //打开文件,读取内容
        FILE* fp = fopen(gbk_name.c_str(), "rb");
        //文件的大小
        fseek(fp, 0, SEEK_END);
        int filesize = ftell(fp);

        //读取内容
        fseek(fp, 0, SEEK_SET);
        char* buf = new char[filesize + 1];

        int n = fread(buf, 1, filesize, fp);
        if (n>0)
        {
            buf[n] = 0;
            //读取内容  转换为QString 显示到界面文本框中
            ui->en_Text->setPlainText(GBK::ToUnicode(buf));
        }
        delete [] buf; //释放内存
        fclose(fp); //关闭文件


    }
    return 0;
}

//[保存]
int DES_UI::OnBtnSaveClicked()
{
    //保存文件
    QString filepath = QFileDialog::getSaveFileName(
        this,//父窗口
        GBK::ToUnicode("选择文件") //标题Caption
    );

    //
    if (filepath.length() > 0)
    {
        QString text = ui->de_Text->toPlainText(); // 获取文本框字符
        string gbk_text = GBK::FromUnicode(ui->de_Text->toPlainText()); //转换为GBK  C风格的字符串

        string gbk_filename = GBK::FromUnicode(filepath);// 将读取的文件路径,转换为GBK形式

        //打开文件
        FILE* fp = fopen(gbk_filename.c_str(), "wb");

        //写入文件
        fwrite(gbk_text.c_str(), 1,gbk_text.length(), fp);
        fclose(fp); //关闭文件


    }
    return 0;
}
