#ifndef CWIN_SCHEDULER_MODEL
#define CWIN_SCHEDULER_MODEL

#include <QObject>
#include <QSettings>

class CWinSchedulerView;
class CSupervision;
class QTimer;

struct Sequence{
    int iStream;
    int iDuree;
};
class CWinSchedulerModel: public QObject
{
	Q_OBJECT
public:
	CWinSchedulerModel(CSupervision* argpSupervision, CWinSchedulerView* argpView);
	
	QString getNbCycleAvantZero()const;
	QString getRemoteControl()const;
	QString getConsigneTemperature()const;
	QString getConsigneGain()const;
	QString getReglagePression()const;
	QString getTempsVoieAttente()const;
	QString getNumEscalveJBUS();
    QString getLblConfigSeuil(int arg_numStream, int arg_numMeasure)const;
    QString getLblConfigSeuil(int arg_index)const;
    int getConfigSeuil(int arg_numStream, int arg_numMeasure)const;
    int getNbSequence()const;
    int getNbMeasure()const;
    int getNbStream()const;
    Sequence getSequence(int arg_numSeq) const;

	QString getYear();
	QString getMonth();
	QString getDay();
	QString getHour();
	QString getMinute();

	void setYear(const QString arg);
	void setMonth(const QString arg);
	void setDay(const QString arg);
	void setHour(const QString arg);
	void setMinute(const QString arg);
    void setDateTime(const QString arg_Year, const QString arg_Month, const QString arg_Day, const QString arg_Hour, const QString arg_Minute);
	void setNbCycleAvantZero(QString arg_nbCycle);
	void setRemoteControl(QString arg_nbCycle);
	void setConsigneTemperature(QString arg_nbCycle);
	void setConsigneGain(QString arg_nbCycle);
	void setReglagePression(QString arg_nbCycle);
	void setTempsVoieAttente(QString arg_nbCycle);
	void setNumEscalveJBUS(QString arg_numEscalve);
    void setSequence(Sequence arg_seq, int arg_numSeq);
    void setConfigSeuil(int arg_index, int arg_config);
    void saveSequences();
    void deleteSequence(int arg_numSeq);
    QString sGetPrivateProfileString(const QString arg_sSection, const QString arg_sKey, const QString arg_sDefault, const QString arg_sFileIni);
	bool bWritePrivateProfileStringS(const QString arg_sSection, const QString arg_sKey, const QString arg_sValue, const QString arg_sFileIni);
    QString sGetPrivateProfileString2(const QString arg_sSection, const QString arg_sKey, const QString arg_sDefault, const QString arg_sFileIni);

public slots:
	
private :
	void setConnexion();

private:
	//Coté supervision connexion aux données
	CSupervision* m_pSupervision;
	CWinSchedulerView* m_pView;
	QTimer *m_timer;

};

#endif