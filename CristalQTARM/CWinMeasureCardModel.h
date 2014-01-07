#ifndef CWIN_MEASURE_CARD_MODEL
#define CWIN_MEASURE_CARD_MODEL

#include "CCardJBusModel.h"
#include <QObject>
#include <QVector>

class CWinMeasureCardView;
class CSupervision;
class CStreamModel;

class QThreadPool;
class QString;
class QRunnbale;
class QMutex;


class CWinMeasureCardModel: public QObject, CCardJBusModel
{
	Q_OBJECT
public:
	CWinMeasureCardModel(CSupervision* argpSupervision);//, CWinMeasureCardView* argpView);
	
	void cmdOrganne(const int& nNumOrganne, const bool& bRelaisActif);
	QVector<QString> getVectorLocalLabels()const{return m_vLocalLabels;};
	QVector<bool> getVectorLocalSecuriteOn()const{return m_vLocalSecuriteOn;};
	
    void sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface);


public slots:
	


private:
	//Coté supervision connexion aux données
	CSupervision* m_pSupervision;
	//CWinMeasureCardView* m_pView;
	CElemCycleStep m_cycleStep;
	//QTimer *m_timer;

	QVector<QString> m_vLocalLabels;
	QVector<bool> m_vLocalSecuriteOn;

    QThreadPool* m_threadPool;
    QMutex* m_mutex;
};

#endif