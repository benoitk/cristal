#include "CCmdJBusRunnable.h"
#include "CCardJBusModel.h"

CCmdJBusRunnable::CCmdJBusRunnable(CCardJBusModel * arg_extCard, const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface)
     :m_JBusCard(arg_extCard), m_numRQT(arg_numRQT), m_elemList(arg_elemList), m_interface(arg_interface)
{
    this->setAutoDelete(true);
}

void CCmdJBusRunnable::run()
{
    m_JBusCard->sendCmdJBus(m_numRQT, m_elemList, m_interface);
}

