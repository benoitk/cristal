#ifndef CWIN_EXTERNAL_CARD_VIEW
#define CWIN_EXTERNAL_CARD_VIEW

#include <QMainWindow>
#include <QList>
#include "CPushButton.h"
class CWinExternalCardControler;
class CWinExternalCardModel;
class QPushButton;
class QRadioButton;
class QTabWidget;

class CWinExternalCardView : public QMainWindow
{
	Q_OBJECT
public:
	CWinExternalCardView(CWinExternalCardControler* argpControler, QWidget *parent = 0, Qt::WindowFlags flags = 0);
	
	void setModel(CWinExternalCardModel* argpModel){m_pModel = argpModel; init();};

	void setValMaxConvertisseur(const QString& arg_sValue){m_btValMaxConvertisseur->setText(arg_sValue);};
	void setValMinConvertisseur(const QString& arg_sValue){m_btValMinConvertisseur->setText(arg_sValue);};
	
public slots:

private:
	void init();
	void setConnexion();
public:
	void setEnabledBtOnRelais(int numRelais, bool bEnabled){m_listBtOnRelais[numRelais]->setEnabled(bEnabled);};
	void setEnabledBtOffRelais(int numRelais, bool bEnabled){m_listBtOffRelais[numRelais]->setEnabled(bEnabled);};


private:
	CWinExternalCardModel* m_pModel;
	CWinExternalCardControler* m_pControler;
	QTabWidget* m_tabWidget;
	
	QPushButton* m_btBack;
	QPushButton* m_btNextPage;
	QPushButton* m_btPreviousPage;
	
	//onglet 4-20 
	QPushButton* m_btValAna;
	QPushButton* m_btValMaxConvertisseur;
	QPushButton* m_btValMaxConvertisseurPlus;
	QPushButton* m_btValMaxConvertisseurMoins;
	QPushButton* m_btValMinConvertisseur;
	QPushButton* m_btValMinConvertisseurPlus;
	QPushButton* m_btValMinConvertisseurMoins;
	//QSlider* m_sliderValAna;
	QRadioButton* m_btRadioTest4mA;
	QRadioButton* m_btRadioTest12mA;
	QRadioButton* m_btRadioTest20mA;

	QList<QPushButton*> m_listBtBack;
	QList<CPushButton*> m_listBtOnRelais;
	QList<CPushButton*> m_listBtOffRelais;

    
};

#endif
