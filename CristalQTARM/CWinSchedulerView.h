#ifndef CWIN_SCHEDULER_VIEW
#define CWIN_SCHEDULER_VIEW
#ifdef RES_640_480
    #define MAX_SEQUENCE 12
#else
    #define MAX_SEQUENCE 6
#endif

#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QList>

class CWinSchedulerControler;
class CWinSchedulerModel;
class CPushButton;
class QTabWidget;

struct SequenceRow{
    CPushButton* btNumVoie;    
    CPushButton* btTempsSeq;    
    CPushButton* btDelete;    
};

class CWinSchedulerView : public QWidget
{
	Q_OBJECT
public:
	CWinSchedulerView(CWinSchedulerControler* argpControler, QWidget *parent = 0, Qt::WindowFlags flags = 0);
	
	void setModel(CWinSchedulerModel* argpModel);
	void loadPage();
	QString getNbCyleAvantZeroValue()const{return m_btNbCyleAvantZero->text();};
	QString getNbCyleAvantZeroLbl()const{return m_lblNbCyleAvantZero->text();};
	void setNbCyleAvantZeroValue(const QString& arg_sValue);

	QString getRemoteCtrlValue()const{return m_btRemoteCtrl->text();};
	QString getRemoteCtrlLbl()const{return m_lblRemoteCtrl->text();};
	void setRemoteCtrlValue(const QString& arg_sValue);

    QString getConsigneTemperatureValue()const{return m_btConsigneTemperature->text();};
	QString getConsigneTemperatureLbl()const{return m_lblConsigneTemperature->text();};
	void setConsigneTemperatureValue(const QString& arg_sValue);

    QString getConsigneGainValue()const{return m_btConsigneGain->text();};
	QString getConsigneGainLbl()const{return m_lblConsigneGain->text();};
	void setConsigneGainValue(const QString& arg_sValue);

    QString getReglagePressionValue()const{return m_btRegalgePression->text();};
	QString getReglagePressionLbl()const{return m_lblRegalgePression->text();};
	void setReglagePressionValue(const QString& arg_sValue);

    QString getTempsVoieAttenteValue()const{return m_btTempsVoieAttente->text();};
	QString getTempsVoieAttenteLbl()const{return m_lblTempsVoieAttente->text();};
	void setTempsVoieAttenteValue(const QString& arg_sValue);

    QString getNumEscalveJBUSValue()const{return m_btNumEscalveJBUS->text();};
	QString getNumEscalveJBUSLbl()const{return m_lblNumEscalveJBUS->text();};
	void setNumEscalveJBUSValue(const QString& arg_sValue);

    void setConfigSeuil(int arg_numBt, int arg_value);
	
	void setYear(const QString& arg_sValue){m_btYear->setText(arg_sValue);};
	void setMonth(const QString& arg_sValue){m_btMonth->setText(arg_sValue);};
	void setDay(const QString& arg_sValue){m_btDay->setText(arg_sValue);};
	void setHour(const QString& arg_sValue){m_btHour->setText(arg_sValue);};
	void setMinute(const QString& arg_sValue){m_btMinute->setText(arg_sValue);};

	QString getYear()const{ return m_btYear->text();};
	QString getMonth()const{ return m_btMonth->text();};
	QString getDay()const{ return m_btDay->text();};
	QString getHour()const{ return m_btHour->text();};
	QString getMinute()const{ return m_btMinute->text();};

  
public slots:

private:
	void init();
	
	QPushButton* m_btBack;
	QPushButton* m_btNextPage;
	QPushButton* m_btPreviousPage;
    CWinSchedulerModel* m_pModel;
	CWinSchedulerControler* m_pControler;

	QPushButton* m_btNbCyleAvantZero;
	QLabel* m_lblNbCyleAvantZero;

	QPushButton* m_btRemoteCtrl;
	QLabel* m_lblRemoteCtrl;

    QPushButton* m_btConsigneTemperature;
	QLabel* m_lblConsigneTemperature;

    QPushButton* m_btRegalgePression;
	QLabel* m_lblRegalgePression;

    QPushButton* m_btTempsVoieAttente;
	QLabel* m_lblTempsVoieAttente;

    QPushButton* m_btNumEscalveJBUS;
	QLabel* m_lblNumEscalveJBUS;
    
    QPushButton* m_btConsigneGain;
	QLabel* m_lblConsigneGain;

    QList<SequenceRow> m_listSequenceRow;
    QList<QPushButton*> m_listBtConfigSeuil;

    QTabWidget* m_tabWidget;

	QPushButton* m_btYear;
	QPushButton* m_btMonth;
	QPushButton* m_btDay;
	QPushButton* m_btHour;
	QPushButton* m_btMinute;


};

#endif
