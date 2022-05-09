#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <qvector.h>
#include <QTextCodec>
#include <QtCore>
#include <QTextDecoder>
#include "QMessageBox"
#include <cuchar> /* или #include <uchar.h> */
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    N = BN_new();
    BIGNUM *first = BN_new();
    BIGNUM *second = BN_new();
    //числа были подобраны на сторонних сайтах, возможо сделать
    //генерацию простых больших чисел программными средствами, однако, это
    //в значительное мере усложняет реализацию поиска S и e
    char p_str[] = "68896494657191156236802789171";
    char p_str1[] = "57418272345461691784089528599";
    BN_dec2bn(&p, p_str);
    BN_dec2bn(&q, p_str1);
    // переменная без которой не запустится, используется для хранения промежуточных результатов вычисления
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    // умножение больших чисел, результат сохранится в N
    BN_mul(N, p, q, ctx);
    // задаём число 1, как ти большого числа, чтобы можно было применить функцию
    char p_str3[] = "1";
    BIGNUM *one = BN_new();
    BN_dec2bn(&one, p_str3);
    //далее идет поиск функции Эйлера
    // разность больших чисел (большого числа и 1 в давнном случае)
    // в first запишется первый множитель необходимый для вычисления функции Эйлера
    BN_sub(first, p, one);
    // в second запишется второй множитель необходимый для вычисления функции Эйлера
    BN_sub(second, q, one);
    //вычисляется поседнее действия для получения функции Эйлера, результат будет записан в перемнную d
    BIGNUM *d = BN_new();
    BN_mul(d, first, second, ctx);
    BN_free(p);
    BN_free(q);
    BN_free(d);
    BN_CTX_free(ctx);
    BN_free(second);
    BN_free(first);
    BN_free(one);
    ui->setupUi(this);
}
MainWindow::~MainWindow()
{
    // освобождение памяти от глобальных переменных в конце работы программы
    BN_free(N);
    BN_free(s);
    delete ui;
}


void MainWindow::on_shifr_clicked()
{
    ui->text_unshifr->clear(); // очищаем поле для вывода зашифрованного текста
    // QString будет хранить в себе данные в кодировке Unicode(стандарт программного обеспечения)
    // используя str.at(i).unicode() можно обратиться к коду определенного символа
    // в данной кодировке, из-за того, что мы можем обратиться к каждому символу отдельно
    // можно считать, что мы разбили сообщение на множество блоков по одному символу
    QString str = ui->text_shifr->text();
    if (!str.isEmpty())
    {
        QString str2;
        QString str3;
        const char *c_str2;
        int uncd;
        QByteArray ba;
        BIGNUM *num = BN_new();
        // выбирается число s <= d и взаимно простое с d
        // s является простым числом, поэтому оно автоматически взаимно простое с d
        // это число и будет являться открытым ключом
        s = BN_new();
        char p_str4[] = "3955917693874248167065981120544441524673953088996879683619";
        BN_dec2bn(&s, p_str4);
        BIGNUM *dv = BN_new();
        BN_CTX *ctx;
        ctx = BN_CTX_new();
        char p_str3[] = "1";
        BIGNUM *res = BN_new();
        for (int i = 0; i < str.size(); i++)
        {
            // Выполняются преобразования, чтобы можно было преобразовать код символа
            // В массив const char*, чтобы мы могли преобразовать его в BIGNUM для вычислений
            uncd = int(str.at(i).unicode());
            str2 = QString::number(uncd);
            ba = str2.toLocal8Bit();
            c_str2 = ba.data();
            num = BN_new();
            BN_dec2bn(&num, c_str2);
            BN_dec2bn(&res, p_str3);
            // с помощью битовых сдвигов очень быстро возводим число в степень по модулю
                while(!BN_is_zero(s)){
                     if (BN_is_bit_set(s, 0)){
                       BN_mul(res, res, num, ctx);
                       BN_div(dv, res, res, N, ctx);
                     }
                     BN_div(dv, num, num, N, ctx);
                     BN_mul(num, num, num, ctx);
                     BN_div(dv, num, num, N, ctx);
                     BN_rshift1(s, s);
                   }
            // восстановление ключа
            BN_dec2bn(&s, p_str4);
            // преобразуем BIGNUM в QString, чтобы вывест его на интерфейс
            char * number_str2 = BN_bn2dec(res);
            ui->text_unshifr->setText(number_str2);
            str3 = str3 + ui->text_unshifr->toPlainText();
            // ставим пробелы после каждого блока, кроме последнего, чтобы разделить их
            if (i < str.size() - 1)
                str3 = str3 + " ";
            ui->text_unshifr->setText(str3);
        }
        // освобождаем память
        BN_free(num);
        BN_free(res);
        BN_free(dv);
        BN_CTX_free(ctx);
    }
    else
    {
        QMessageBox::warning(this, "Внимание","Столько места, а пусто, почему...");
    }

}

void MainWindow::on_un_shif_clicked()
{
    QString str, str2, str3;
    str = ui->text_unshifr->toPlainText();
    if (!str.isEmpty())
    {
        ui->text_shifr->clear(); // очистка поля для расшифрованного текста
        int x;
        char * number_str2;
        int namelen;
        QString  result;
        BIGNUM *e = BN_new();
        // закрытый ключ
        char p_str4[] = "2508630732700742740090622174003792186378604397900460287199";
        BN_dec2bn(&e, p_str4);
        const char *c_str2;
        QByteArray ba;
        int j = str.count(QChar(' ')); // считаем количество пробелов, чтобы узнать количество блоков
        // подготовка данных для дальнейших вычислений
        BIGNUM *dv = BN_new();
        BIGNUM *num = BN_new();
        BN_CTX *ctx;
        ctx = BN_CTX_new();
        char p_str3[] = "1";
        BIGNUM *res = BN_new();


        for (int i = 0; i < j + 1; i++)
        {
            if (i < j)
            {
                str2 = str.left(str.indexOf(' ')); // // получаем блок, путем считывания строки до пробела
                str.remove(0, str2.length() + 1);
            }
            else
                str2 = str;
            // переводи число записанное в QString в BIGNUM
            ba = str2.toLocal8Bit();
            c_str2 = ba.data();
                BN_dec2bn(&num, c_str2);
                BN_dec2bn(&res, p_str3);
                // возводим в степень по модулю с помощью битовых сдвигов
                    while(!BN_is_zero(e)){
                         if (BN_is_bit_set(e, 0)){
                           BN_mul(res, res, num, ctx);
                           BN_div(dv, res, res, N, ctx);
                         }
                         BN_div(dv, num, num, N, ctx);
                         BN_mul(num, num, num, ctx);
                         BN_div(dv, num, num, N, ctx);
                         BN_rshift1(e, e);
                       }
                // восстановление ключа
                BN_dec2bn(&e, p_str4);
                // преобразование полученного числа в текст кодировки unicode
                number_str2 = BN_bn2dec(res);
                namelen = strlen(number_str2);
                result = QString::fromUtf8((const char *)number_str2,namelen);
                x = result.toInt(/*0,10*/);
                ui->text_shifr->setText(QString(QChar(x))); // с помощью данной записи можно получить символы unicode по коду
                str3 = str3 + ui->text_shifr->text();
                ui->text_shifr->setText(str3); // вывод расшифрованного сообщения на интерфейс
        }
        // очистка
         BN_free(num);
         BN_free(e);
         BN_free(res);
         BN_free(dv);
         BN_CTX_free(ctx);
    }
    else
    {
         QMessageBox::warning(this, "Внимание","Введите хоть что-нибудь...");
    }

}
