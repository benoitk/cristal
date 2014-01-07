#ifndef CWIN_MEASURE_CARD_VIEW
#define CWIN_MEASURE_CARD_VIEW

#include <QWidget>
#include <QVector>
#include <QPushButton>

class CWinMeasureCardControler;
class CWinMeasureCardModel;


class CWinMeasureCardView : public QWidget
{
	Q_OBJECT
public:
	CWinMeasureCardView(CWinMeasureCardControler* argpControler, QWidget *parent = 0, Qt::WindowFlags flags = 0);
	
	void setConnexion();
	void setModel(CWinMeasureCardModel* argpModel){m_pModel = argpModel; init();};

	void setEnabledBtOnLocal1(bool bEnabled){m_vBtOnLocal.at(0)->setEnabled(bEnabled);};
	void setEnabledBtOffLocal1(bool bEnabled){m_vBtOffLocal.at(0)->setEnabled(bEnabled);};
	void setEnabledBtOnLocal2(bool bEnabled){m_vBtOnLocal.at(1)->setEnabled(bEnabled);};
	void setEnabledBtOffLocal2(bool bEnabled){m_vBtOffLocal.at(1)->setEnabled(bEnabled);};
	void setEnabledBtOnLocal3(bool bEnabled){m_vBtOnLocal.at(2)->setEnabled(bEnabled);};
	void setEnabledBtOffLocal3(bool bEnabled){m_vBtOffLocal.at(2)->setEnabled(bEnabled);};
	void setEnabledBtOnLocal4(bool bEnabled){m_vBtOnLocal.at(3)->setEnabled(bEnabled);};
	void setEnabledBtOffLocal4(bool bEnabled){m_vBtOffLocal.at(3)->setEnabled(bEnabled);};
	void setEnabledBtOnLocal5(bool bEnabled){m_vBtOnLocal.at(4)->setEnabled(bEnabled);};
	void setEnabledBtOffLocal5(bool bEnabled){m_vBtOffLocal.at(4)->setEnabled(bEnabled);};
	void setEnabledBtOnLocal6(bool bEnabled){m_vBtOnLocal.at(5)->setEnabled(bEnabled);};
	void setEnabledBtOffLocal6(bool bEnabled){m_vBtOffLocal.at(5)->setEnabled(bEnabled);};
	
public slots:

private:
	void init();
	/*QPushButton* m_btOnStirrer;
	QPushButton* m_btOffStirrer;
	QPushButton* m_btOnDoor;
	QPushButton* m_btOffDoor;
	QPushButton* m_btOnValve;
	QPushButton* m_btOffValve;
	QPushButton* m_btOnHeater;
	QPushButton* m_btOffHeater*/;
	QPushButton* m_btBack;
	QPushButton* m_btNextPage;
	QPushButton* m_btPreviousPage;
    CWinMeasureCardModel* m_pModel;
	CWinMeasureCardControler* m_pControler;

	QVector<QPushButton*> m_vBtOnLocal;
	QVector<QPushButton*> m_vBtOffLocal;
};

#endif
