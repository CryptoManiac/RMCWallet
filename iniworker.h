#ifndef INIWORKER_H
#define INIWORKER_H

#include <QFile>

class CIniworker
{
public:
    enum JobType
    {
        J_NONE=0,
        W_DUMMY=1,
        W_PROXY=2,
        R_PROXY=3
    };
    CIniworker();
    ~CIniworker();
    void Write(const JobType& action);
    void Read(const JobType& action);
private:
    QFile iniFile;
};

#endif // INIWORKER_H
