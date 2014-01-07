#ifndef CWIN_SELECTUR_MODEL
#define CWIN_EV_POMPE_MODEL

#include "CCardJBusModel.h"
#include <QObject>
#include <QVector>

class CSupervision;
class CWinElecTestView;

class QThreadPool;
class QString;
class QRunnbale;
class QMutex;

class CWinStreamSelectorModel: public QObject, CCardJBusModel
{
	Q_OBJECT
public:
    CWinStreamSelectorModel(CSupervision* argpSupervision);//, CWinEVPompeView* argpView);
   
    void cmdSelectionVoie(int arg_nNumVoie);
    int getNbStream()const;

    void sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface);


private:
	//Coté supervision connexion aux données
    CSupervision* m_pSupervision;
    CWinElecTestView* m_pView;
    CElemCycleStep m_cycleStep;
    
    QThreadPool* m_threadPool;
    QMutex* m_mutex;
};

#endif