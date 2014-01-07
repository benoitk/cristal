#ifndef CWIN_EXTERNAL_CARD_MODEL
#define CWIN_EXTERNAL_CARD_MODEL

#include "CCardJBusModel.h"
#include <QObject>
#include <QVector>
#include <QList>
#include <QTimer>

class CWinElecTestView;
class CSupervision;

class QThreadPool;
class QString;
class QRunnbale;
class QMutex;


class CWinExternalCardModel: public QObject, CCardJBusModel
{
	Q_OBJECT
public:
	CWinExternalCardModel(CSupervision* argpSupervision, CWinElecTestView* argpView);//, CWinExternalCardView* argpView);
	
	void cmdRelais(const int& nNumRelais,const bool& bRelaisActif);
	void cmdSortieAnalogique(const int& nNumSortie, const int& arg_nValeurAna);
	void setValMaxConvertisseur(int arg_numSortie, const QString& arg_sVal);
	void setValMinConvertisseur(int arg_numSortie, const QString& arg_sVal);
	QString getLblDigiOut(const int& nNumDigiOut){return m_vDigiOutLabels.at(nNumDigiOut);};
	QString getLblDigiIn(const int& nNumDigiOut){return m_vDigiInLabels.at(nNumDigiOut);};
	QString getLblAnalogOut(const int& nNumDigiOut){return m_vAnalogOutLabels.at(nNumDigiOut);};
	QVector<QString> getVectorLblDigiOut(){return m_vDigiOutLabels;};
	QString getLblValAna()const;
	QString getLblMesure()const;
	QString getLblValMaxConvertisseur()const;
	QString getLblValMinConvertisseur()const;
	QString getUniteValAna()const;
	QString getUniteMesure()const;
	QString getUniteValMaxConvertisseur()const;
	QString getUniteValMinConvertisseur()const;
	QString getValueValAna()const;
	QString getValueMesure()const;
	QString getValueValMaxConvertisseur(int arg_numSortie)const;
	QString getValueValMinConvertisseur(int arg_numSortie)const;
    bool getEtatEntree(int arg_numEntree)const;
    bool getEtatEntreePhysique(int arg_numEntree)const;
	int getNbDigitOut()const{return m_nNumSDVirtuel;};
	int getNbDigitIn()const{return m_nNumEDVirtuel;};
	int getNbAnalogOut()const{return m_nNumSAVirtuel;};
    void setStartTimerCmdEntree(){m_timerCmdEntree->start();};
    void setStopTimerCmdEntree(){m_timerCmdEntree->stop();};

    void sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface);


public slots:
	void trigerWatchdog();
	void slotTrigerDigitOut8();
	void cmdGetEntrees();

private:
	void setRequetesJBus();
private:
	//Coté supervision connexion aux données
	CSupervision* m_pSupervision;
	CWinElecTestView* m_pView;
	CElemCycleStep m_cycleStep;

	QVector<QString> m_vDigiOutLabels;
	QVector<QString> m_vDigiInLabels;
	QList<bool> m_listDigiOutSecurite;
	QList<bool> m_listDigiInSecurite;
	QList<int> m_listNumCarteED;
	QList<int> m_listNumEntreePhysiqueED;
	QList<int> m_listNumCarteSA;
	QList<int> m_listNumMesureSA;
	QVector<QString> m_vAnalogOutLabels;
    QThreadPool* m_threadPool;
    QMutex* m_mutex;
	int m_nNumSDVirtuel;
	int m_nNumSAVirtuel;
	int m_nNumEDVirtuel;

    QTimer* m_timerCmdEntree;

};

#endif