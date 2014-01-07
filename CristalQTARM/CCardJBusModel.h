#ifndef CARD_JBUS_MODEL
#define CARD_JBUS_MODEL

#include "header.h"
//Model de class pour toutes les cartes qui communique en JBus
class CCardJBusModel
{
public:
    
    virtual void sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface)=0;
};

#endif
