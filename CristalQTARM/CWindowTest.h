#ifndef CWINDOW_TEST
#define CWINDOW_TEST
#include "CWindowTestCartesExt.h"
#include "stdafx.h"
#include "header.h"
#include "header_qt.h"

class CWindowTest: public QDialog
{
	Q_OBJECT

public:
	CWindowTest(CListStream* argAnalyseur,CCarteIO* argCarteIO, QWidget *parent = 0, Qt::WFlags flags = 0);
	~CWindowTest();

public slots:
	void btAcquitterPressed();

private :
	
	void setConnections();



private:

	//Présentation
	QGroupBox *mainGroupBox;
	QGridLayout *mainLayout;
	//
	QPushButton *btCarteMesure;
	QPushButton *btEVPompe;
	QPushButton *btCarteExt;
	QPushButton *btPanelPC;
	QPushButton *btAnalyseur;
	QPushButton *btClose;


	//Obj métier
	CListStream* m_pAnalyseur;
	QLabel *m_label;
	QLabel * m_label2;
	QLabel *lblCurrentStream;
	CStream* m_oVoie;
	CMesure* m_pMesure;
	QTimer *m_timer;
	CCarteIO* m_oCarteIO;
	//fenêtre
	CWindowTestCartesExt* oWinTestCartesExt;

};

#endif // CWINDOW_TEST