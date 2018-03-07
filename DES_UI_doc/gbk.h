#include <QString>
#include <QTextCodec>
#include <string>

using std::string;

class GBK
{
public:
    //QString(Unicode) --> std::string(GBK)
    //QTextCodec 用于手工转换编码(QString内部调用此类)
    static string FromUnicode(const QString& qstr)
    {
        QTextCodec* pCodec = QTextCodec::codecForName("gb2312"); //GBK
        if (!pCodec) return "";

        QByteArray arr = pCodec->fromUnicode(qstr);
        string cstr = arr.data();
        return cstr;
    }

    //GBK --> QString
    //std::string(GBK)--> QString(Unicode)
    static QString ToUnicode(const string& cstr)
    {
        QTextCodec* pCodec = QTextCodec::codecForName("gb2312");
        if (!pCodec) return "";

        QString qstr = pCodec->toUnicode(cstr.c_str(), cstr.length());
        return qstr;
    }
};
