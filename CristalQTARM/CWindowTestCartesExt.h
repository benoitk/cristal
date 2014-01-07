#ifndef CWINDOW_TEST_CARTES_EXT
#define CWINDOW_TEST_CARTES_EXT
#include "stdafx.h"
#include "header.h"
#include "header_qt.h"

class CWindowTestCartesExt: public QDialog
{
	Q_OBJECT

public:
	CWindowTestCartesExt(CListStream* argAnalyseur,CCarteIO* argCarteIO, QWidget *parent = 0, Qt::WFlags flags = 0);
	~CWindowTestCartesExt();

public slots:
	void btbtSD1Pressed();
	void btbtSD2Pressed();

private :
	
	void setConnections();



private:

	//Présentation
	QGroupBox *mainGroupBox;
	QGroupBox *actionGroupBox;
	QGridLayout *mainLayout;
	//
	QPushButton *btSD1;
	QPushButton *btSD2;
	QPushButton *btSD3;
	QPushButton *btSD4;
	QPushButton *btSD5;
	QPushButton *btSD6;
	QPushButton *btSD7;
	QPushButton *btSD8;
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
	CElemCycleStep cycleStep;
	bool bBtSD1Pressed;

};

#endif // CWINDOW_TEST_CARTES_EXT