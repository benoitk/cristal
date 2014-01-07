#ifndef CWIN_EV_POMPE_MODEL
#define CWIN_EV_POMPE_MODEL

#include "CCardJBusModel.h"
#include <QObject>
#include <QVector>

class CWinEVPompeView;
class CSupervision;
class CStreamModel;

class QThreadPool;
class QString;
class QRunnbale;
class QMutex;

class CWinEVPompeModel: public QObject, CCardJBusModel
{
	Q_OBJECT
public:
    CWinEVPompeModel(CSupervision* argpSupervision);//, CWinEVPompeView* argpView);
   
    void cmdEv(const int& nNumEv, const bool& bRelaisActif);
    void cmdPompe(const int& nNumPompe, const bool& bRelaisActif);
    void cmdConfigPompes();
    void cmdPompesOff();
    QString getPumpLabel(const int& nNumPump)const{return m_vPumpLabels.at(nNumPump);};
    QString getEVLabel(const int& nNumEV)const{return m_vEVLabels.at(nNumEV);};
    QVector<QString> getVectorPumpLabels()const{return m_vPumpLabels;};
    QVector<QString> getVectorEVLabels()const{return m_vEVLabels;};

    void sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface);


private:
	//Coté supervision connexion aux données
    CSupervision* m_pSupervision;
    CWinEVPompeView* m_pView;
    CElemCycleStep m_cycleStep;
    
    QVector<QString> m_vPumpLabels;
    QVector<QString> m_vEVLabels;

    QThreadPool* m_threadPool;
    QMutex* m_mutex;
};

#endif