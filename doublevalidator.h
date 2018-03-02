#ifndef DOUBLEVALIDATOR_H
#define DOUBLEVALIDATOR_H

#include <QObject>
#include <QDoubleValidator>

class DoubleValidator : public QDoubleValidator
{
public:
    DoubleValidator(double bottom, double top, int decimals, QObject *parent = 0)
        :QDoubleValidator( bottom, top, decimals, parent) {};
    DoubleValidator(QObject *parent = 0)
        :QDoubleValidator(parent) {};
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
        const QValidator::State origState = QDoubleValidator::validate( input, pos );
        if( ( origState == QValidator::Intermediate ) && ( input.toDouble() > top() ) )
        {
            return QValidator::Invalid;
        }
        else
        {
            return origState;
        }
    }
};

#endif // DOUBLEVALIDATOR_H
