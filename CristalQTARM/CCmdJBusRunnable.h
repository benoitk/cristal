#ifndef CMD_JBUS_RENNABLE
#define CMD_JBUS_RENNABLE

#include "header.h"
#include <QRunnable>

class CWinExternalCardModel;
class CCardJBusModel;

class CCmdJBusRunnable : public QRunnable
{

public:
  ;
    CCmdJBusRunnable(CCardJBusModel * arg_extCard,const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface);
 
    void run();
private:
    int m_numRQT;
    CElemList* m_elemList;
    CEnumInterface& m_interface;
    CCardJBusModel* m_JBusCard;
};

#endif