#ifndef INTVALIDATOR_H
#define INTVALIDATOR_H

#include <QObject>
#include <QIntValidator>

class IntValidator : public QIntValidator
{
public:
    IntValidator(double bottom, double top, QObject *parent = nullptr)
        :QIntValidator( bottom, top, parent) {};
    IntValidator(QObject *parent = nullptr)
        :QIntValidator(parent) {};
    QValidator::State validate(QString &input, int &pos) const
    {
        /*
         * Original Qt Documentation:
         * ---------
         * QDoubleValidator::validate()
         * Returns Intermediate if input contains a double that is
         * outside the range or is in the wrong format; e.g. with too many
         * digits after the decimal point or is empty.
         * ---------
         * Problem: Not what the user expects.
         * Example: Range 0.0-10.0 with 1 digit (QDoubleValidator( 0, 10, 1, parent ) ):
         * QDoubleValidator::validate() reports intermediate for "10.3".
         * However we expect invalid instead and QLineEdit to decline input.
         * Fix this by overloading the validate() operator.
         */
        const QValidator::State origState = QIntValidator::validate( input, pos );
        if( ( origState == QValidator::Intermediate ) && ( input.toInt() > top() ) )
        {
            return QValidator::Invalid;
        }
        else
        {
            return origState;
        }
    }
};

#endif // INTVALIDATOR_H
