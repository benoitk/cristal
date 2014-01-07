#ifndef CWIN_MAIN_MODEL
#define CWIN_MAIN_MODEL


#include "CCardJBusModel.h"
#include <QObject>
#include <QVector>
#include <QTimer>
#include <QString>

class CWinMainView;
class CSupervision;
class CStreamModel;

class QThreadPool;
class QString;
class QRunnbale;
class QMutex;
class QDir;




//Le model gère les données. Il posède un timer qui exécutre la récupération des donnée fréquement.
//La vue est prévenu à chaque changement
//Si une opération sur les données est éxécuté le controler envoie la donnée modifier au model qui fait suivre à la supervision
class CWinMainModel: public QObject, CCardJBusModel
{
		Q_OBJECT
	
public:

    CWinMainModel(CSupervision* argoSupervision, CWinMainView* argoView);
   
    void setConnexion();

    int getNbStream()const;
    int getNbMeasure(int numStream)const;

    QString getEtatAnalyseur()const;
    QString getCurrentStream()const;
    int nGetCurrentStream()const;
    int nGetNombreMesure()const;
	int nGetPreviousStream()const;
    QString getNbCycleAvantBlanc();
    QString getNameStep()const;
    QString getMesureValueUnit(int numStream, int numMeasure)const;
    QString getMesureValueLbl(int numStream, int numMeasure)const;
    QString getMesureValue(int numStream, int numMeasure)const;
    QString getTemperatureCuve();
    QString getPressionEau();
    QString getMesureOptique();
    QString getOpticalGainValue()const;
    QString getOpticalGainLbl()const;
    QString getOpticalGainUnit()const;
    QString getZeroOpticalMeasurementValue()const;
    QString getZeroOpticalMeasurementLbl()const;
    QString getZeroOpticalMeasurementUnit()const;
    QString getOpticalMeasurementLbl()const;
    QString getOpticalMeasurementUnit()const;
    QString getOpticalMeasurementValue()const;
    QString getAbsorbanceValueLbl()const;
    QString getAbsorbanceValueUnit()const;
    QString getAbsorbanceValueValue()const;

    QString getCurrentStep()const;
    QString getTotalStep()const;
    //QVector<CStreamModel*> getVectorStream(){return m_vectorStream;}; 

    bool getRun()const;
    bool getStop()const;
    bool getPause()const;
    bool getEnAlarm()const;
    bool getStreamStatus(int arg_numStream)const;
    bool getStatusWaterFailure(int arg_numStream)const;
    bool getStatusSeuil(int arg_numStream)const;
    bool getStatusPeriodic(int arg_numStream)const;
    bool getEnPeriodic()const;
    bool getVoieActive(int arg_numStream)const;

    void setStopTimerCycle(){if(m_timerCycle->isActive())m_timerCycle->stop();};
    void setStartTimerCycle(){if(!m_timerCycle->isActive())m_timerCycle->start();};
    void setStopTimerDiag(){if(m_timerDiag->isActive())m_timerDiag->stop();};
    void setStartTimerDiag(){if(!m_timerDiag->isActive())m_timerDiag->start();};

    void setRun();
    void setStop();
    void setStopEndCycle();
    void setPause();
    void setUnpause();
    void setNext();
    void setModeMaintenance(bool arg_bEnMaintenance);

    void checkAgeLog();

    bool getFlagEndCycle();
    float getBoutPlageMax(int arg_iStream=0, int arg_iMeasure=0);
    float getBoutPlageMin(int arg_iStream=0, int arg_iMeasure=0);

    void sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface);
    
public slots:

    void getDataFromSupervision();
    void getDataFromMeasureCard();

private:
    //Coté supervision connexion aux données
    CElemCycleStep m_oCycleStep;
    CSupervision* m_pSupervision;

    //coté model
    //QVector<CStreamModel*> m_vectorStream; 

    QString m_sEtatAnalyseur;
    QString m_sCurrentStream;
    QString m_sNameStep;
    QString m_sMesureValue;
    int m_iCurrentStep;
    int m_iTotalStep;
    int m_iModeSaved;
    bool m_bFlagEndCycle;
    int m_iPreviousStep;

    bool m_bRun;
    bool m_bStop;
    bool m_bPause;
    bool m_bEnAlarm;

   

    CElemCycleStep m_cycleStep;

    CWinMainView* m_pView;

    int m_iTest;

    QTimer *m_timerCycle;
    QTimer *m_timerDiag;

    QDir* m_logFileDir;
    QDir* m_logErrorPrgFileDir;
    QDir* m_logUserFileDir;
    int m_iCptPurgeLog;
    int m_nbrDayRetentionUserLog;
    int m_nbrDayRetentionErrorLog;
    int m_nbrDayRetentionLog;


    QThreadPool* m_threadPool;
    QMutex* m_mutex;
};

#endif