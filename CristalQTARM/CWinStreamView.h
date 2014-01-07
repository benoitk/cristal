#ifndef CWIN_STREAM_VIEW
#define CWIN_STREAM_VIEW

#ifdef RES_640_480
	#define NOMBRE_VALUE_PAR_PAGE 10
#else
	#define NOMBRE_VALUE_PAR_PAGE 5
#endif


#include <QWidget>
#include <QVector>
#include <QList>
#include <QPushButton>
#include <QLabel>
#include "CPushButton.h"

class CWinStreamControler;
class CWinStreamModel;
class QGridLayout;
class QTabWidget;

class CWinStreamView : public QWidget
{
	Q_OBJECT
public:
	CWinStreamView(CWinStreamControler* argoControler, QWidget *parent = 0, Qt::WindowFlags flags = 0);
	
	void setConnexion();
	void setModel(CWinStreamModel* argoModel);

	void setDownBtOnVoieActive(bool bIsDown);
	void setDownBtOffVoieActive(bool bIsDown);
	void setEnabledBtNextPage(bool bActive, int arg_numStream){m_listBtNextPage[arg_numStream]->setEnabled(bActive);};
	void setEnabledBtPreviousPage(bool bActive, int arg_numStream){m_listBtPreviousPage[arg_numStream]->setEnabled(bActive);};

	QString getEditText(int arg_index)const{return m_listBtEdit.at(arg_index)->text();};
	QString getEditTextLbl(int arg_index)const{return m_listLblEdit.at(arg_index)->text();};
	/*QString getEdit1Text(){return m_btEdit1->text();};
	QString getEdit2Text(){return m_btEdit2->text();};
	QString getEdit3Text(){return m_btEdit3->text();};
	QString getEdit4Text(){return m_btEdit4->text();};*/

	void setEditText(int arg_numStream, int arg_numMeasure, int arg_index, int arg_numPage, const QString& arg_sText);
	void setLblPaginationTxt(int arg_nPage, int arg_nNbPage){m_lblPagination->setText(QString::number(++arg_nPage,10)+"/"+QString::number(++arg_nNbPage,10));};


public slots:
	void loadPage(int arg_numStream, int arg_numMeasure, int argnNumPage);
private:
	CWinStreamControler* m_pControler;
	CWinStreamModel* m_pModel;

	//Boutton du menu de droite
	QVector<QPushButton*> m_vectorBtBack;
	QVector<QPushButton*> m_vectorBtApply;

    QTabWidget* m_tabWidget;

	//bouton de nav 
	QList<CPushButton*> m_listBtNextPage;
	QList<CPushButton*> m_listBtPreviousPage;
	QLabel* m_lblPagination;
	//Tab voie
	QPushButton* m_btOnVoieActive;
	QPushButton* m_btOnCycleEnCours;
	QPushButton* m_btOffVoieActive;
	QPushButton* m_btOffCycleEnCours;
	QPushButton* m_btStatus;
	QPushButton* m_btStatusWaterFailure;
	QPushButton* m_btStatusSeuil;

	QLabel* m_lblStatutVoie;
	QLabel* m_lblStatutSeuil;
	QLabel* m_lblStatutDefautEau;
	QLabel* m_lblCptCycle;
	QLabel* m_lblCycleEnCours;

    QLabel* m_lblDefauttVoie;
	QLabel* m_lblDefautEau;
	QLabel* m_lblDefautSeuil;
	QLabel* m_lblVoieActive;

	QList<QGridLayout*> m_listLayoutMesure;

	//Tab mesure
	QList<CPushButton*> m_listBtEdit;
	QList<QLabel*> m_listLblEdit;
	/*QPushButton* m_btEdit1;
	QPushButton* m_btEdit2;
	QPushButton* m_btEdit3;
	QPushButton* m_btEdit4;*/


	void init();

	
};

#endif
