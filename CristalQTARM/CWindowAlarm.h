#ifndef CWINDOW_ALARM
#define CWINDOW_ALARM

#include "stdafx.h"
#include "header.h"
#include "header_qt.h"

class CWindowAlarm: public QDialog
{
	Q_OBJECT

public:
	CWindowAlarm(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CWindowAlarm(){qDebug() << "PIM :CWindowAlarm" << endl;TRACE_LOG_MSG(_T("PIM :CWindowAlarm"));};
	
	void setAnalyseur(CListStream* argAnalyseur);
	void showEvent ( QShowEvent * event );

public slots:
	void btAcquitterPressed();
	void updateAlarms();
private :
	
	void setConnections();



private:

	QGroupBox *mainGroupBox;
	QGridLayout *mainLayout;
	QAction *closeAction;
	QWidget *centralWidget;
	QGroupBox *verticalGroupBox;
	QGroupBox *formGroupBox;
	QListWidget *listWidget;

	QPushButton *btAcquitter;
	QPushButton *btClose;





	CListStream* m_pAnalyseur;
	QLabel *m_label;
	QLabel * m_label2;
	QLabel *lblCurrentStream;
	CStream* m_oVoie;
	CMesure* m_pMesure;
	QTimer *m_timer;


};

#endif // CWINDOW_ALARM