#ifndef CWIN_MAINTENANCE_MODEL
#define CWIN_MAINTENANCE_MODEL

#include "CCardJBusModel.h"
#include <QObject>
#include <QString>
#include <Qtimer>

#include "Network.h"

class CWinMaintenanceView;
class CSupervision;
class CStreamModel;
class QThreadPool;
class QMutex;

class CWinMaintenanceModel: public QObject, CCardJBusModel
{
	Q_OBJECT
public:
	CWinMaintenanceModel(CSupervision* argpSupervision, CWinMaintenanceView* argpView);
	
	void setMesureManuelleVal(const QString& sValue, int arg_numStream, int arg_numMeasure);
	void setOffsetActuelVal(const QString& sValue, int arg_numStream);
	void setOffsetCalculeVal(const QString& sValue, int arg_numStream);
	void setEtalonRefVal(const QString& sValue, int arg_numStream, int arg_numMeasure);
	void setCoefActuelVal(const QString& sValue, int arg_numStream, int arg_numMeasure);
	void setCoefCalculeVal(const QString& sValue, int arg_numStream, int arg_numMeasure);
	void setV0Val(const QString& sValue);
	void setV2Val(const QString& sValue);
	void setIndicateurEauAirVal(const QString& sValue);
	
	
	QString sGetMesureManuelleVal(int arg_numStream, int arg_numMeasure)const;
	QString sGetOffsetActuelVal(int arg_numStream)const;
	QString sGetOffsetCalculeVal(int arg_numStream)const;
	QString sGetEtalonRefVal(int arg_numStream, int arg_numMeasure)const;
	QString sGetCoefActuelVal(int arg_numStream, int arg_numMeasure)const;
	QString sGetCoefCalculeVal(int arg_numStream, int arg_numMeasure)const;
	QString sGetV0Val()const;
	QString sGetV2Val()const;
	QString sGetEtalonEauRefVal()const;
	QString sGetIndicateurEauAirVal()const;
	QString sGetMesurePHVal()const;

	bool bGetCoefStatus(int arg_numStream, int arg_numMeasure)const;
	
	bool bGetOffsetStatus(int arg_numStream)const;
	
	QString sGetMesureManuelleLbl(int arg_numStream, int arg_numMeasure)const;
	QString sGetOffsetActuelLbl(int arg_numStream)const;
	QString sGetOffsetCalculeLbl(int arg_numStream)const;
	QString sGetEtalonRefLbl(int arg_numStream, int arg_numMeasure)const;
	QString sGetCoefActuelLbl(int arg_numStream, int arg_numMeasure)const;
	QString sGetCoefCalculeLbl(int arg_numStream, int arg_numMeasure)const;
    QString sGetCoefSondeActuelLbl(int arg_numMeasure)const;
	QString sGetCoefSondeCalculeLbl(int arg_numMeasure)const;
	QString sGetV0Lbl()const;
	QString sGetV2Lbl()const;
	QString sGetEtalonEauRefLbl()const;
	QString sGetIndicateurEauAirLbl()const;
	QString sGetMesurePHLbl()const;

	
	void passerAnalyseurEnMaintenance();
	void retourAnalyseurDeMaintenance();
	void executeCalib(int arg_numStream);
	void executeCalibInLine(int arg_numStream);
	void executeCleanup(int arg_numStream);
	void executeZero(int arg_numStream);
	void setConnexion();
	QString getNameStep()const{return m_sNameStep;};
	QString getCurrentStep()const{return QString::number(m_iCurrentStep);};
	bool getEnRun()const{return m_bRun;};
	bool getEnStop()const{return m_bStop;};
	bool getCycleMaintenanceEnCours()const;
	bool getCalibEnCours()const;
	bool getCalibInLineEnCours()const;
	bool getZeroEnCours()const;
	bool getCleanupEnCours()const;
	void setStop();
	bool getEnPause()const{return m_bPause;};
	void setEnPause(bool bEnPause);

	QString getTemperatureCuve();
	QString getPressionEau();
	QString getMesureOptique();
	float getOpticalGainValue()const;
	QString getOpticalGainLbl()const;
	QString getOpticalGainUnit()const;
	float getZeroOpticalMeasurementValue()const;
	QString getZeroOpticalMeasurementLbl()const;
	QString getZeroOpticalMeasurementUnit()const;
	QString getOpticalMeasurementLbl()const;
	QString getOpticalMeasurementUnit()const;
	float getOpticalMeasurementValue()const;
	int getNbStream()const;

	void setStopTimerCycle(){if(m_timerCycle->isActive())m_timerCycle->stop();};
	void setStartTimerCycle(){if(!m_timerCycle->isActive())m_timerCycle->start();};
	void setStopTimerDiag(){if(m_timerDiag->isActive())m_timerDiag->stop();};
	void setStartTimerDiag(){if(!m_timerDiag->isActive())m_timerDiag->start();};

    void sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface);

public slots:
	void getDataFromSupervision();
	

private:
	CSupervision* m_pSupervision;
	CWinMaintenanceView* m_pView;
	CElemCycleStep m_cycleStep;
	int iSaveRemoteCtrl;

	QTimer *m_timerCycle;
	QTimer *m_timerDiag;
	QString m_sNameStep;
    int m_iCurrentStep;
	bool m_bRun;
	bool m_bStop;
	bool m_bPause;
    bool m_bEtatVoieAvantMaintenance;

	
    QThreadPool* m_threadPool;
    QMutex* m_mutex;
};

#endif