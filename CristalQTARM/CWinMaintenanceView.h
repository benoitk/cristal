#ifndef CWIN_MAINTENANCE_VIEW
#define CWIN_MAINTENANCE_VIEW

#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QTabWidget>

class CWinMaintenanceModel;
class CWinMaintenanceControler;


class CWinMaintenanceView: public QWidget
{
	Q_OBJECT
public:
	CWinMaintenanceView(CWinMaintenanceControler* argpControler, QWidget *parent = 0, Qt::WindowFlags flags = 0);
	
	void setModel(CWinMaintenanceModel* argpModel){m_pModel = argpModel; init();};
	void setTabIndex(int arg_index){m_tabWidgetCentral->setCurrentIndex(arg_index);};

	void setEnabledBtExecuteCalib(bool bEnabled, int index){m_listBtExecuteCalib.at(index)->setEnabled(bEnabled);};
	void setEnabledBtExecuteCalibInLine(bool bEnabled, int index){m_listBtExecuteCalibInLine.at(index)->setEnabled(bEnabled);};
	void setEnabledBtExecuteZero(bool bEnabled, int index){m_listBtExecuteZero.at(index)->setEnabled(bEnabled);};
	void setEnabledBtExecuteCleanup(bool bEnabled, int index){m_listBtExecuteCleanup.at(index)->setEnabled(bEnabled);};
	
	void setPressedBtExecuteCalib(bool bDown, int index){m_listBtExecuteCalib.at(index)->setDown(bDown);};
	void setPressedBtExecuteCalibInLine(bool bDown, int index){m_listBtExecuteCalibInLine.at(index)->setDown(bDown);};
	void setPressedBtExecuteCleanup(bool bDown, int index){m_listBtExecuteCleanup.at(index)->setDown(bDown);};
	void setPressedBtExecuteZero(bool bDown, int index){m_listBtExecuteZero.at(index)->setDown(bDown);};
	bool getPressedBtExecuteCalib(int index)const{return m_listBtExecuteCalib.at(index)->isDown();};
	bool getPressedBtExecuteCalibInLine(int index)const{return m_listBtExecuteCalibInLine.at(index)->isDown();};
	bool getPressedBtExecuteCleanup(int index)const{return m_listBtExecuteCleanup.at(index)->isDown();};
	bool getPressedBtExecuteZero(int index)const{return m_listBtExecuteZero.at(index)->isDown();};

	void setEnabledBtBack(bool bEnabled){m_btBack->setEnabled(bEnabled);};

	void setEnabledLblCalib(bool bEnabled, int index){m_listLblCalib.at(index)->setEnabled(bEnabled);};
	bool getEnabledLblCalib(int index)const{return m_listLblCalib.at(index)->isEnabled();};
	void setEnabledLblCalibInLine(bool bEnabled, int index){m_listLblCalibInLine.at(index)->setEnabled(bEnabled);};
	bool getEnabledLblCalibInLine(int index)const{return m_listLblCalibInLine.at(index)->isEnabled();};
	void setEnabledLblCleanup(bool bEnabled, int index){m_listLblCleanup.at(index)->setEnabled(bEnabled);};
	bool getEnabledLblCleanup(int index)const{return m_listLblCleanup.at(index)->isEnabled();};
	void setEnabledLblZero(bool bEnabled, int index){m_listLblZero.at(index)->setEnabled(bEnabled);};
	bool getEnabledLblZero(int index)const{return m_listLblZero.at(index)->isEnabled();};

	void razlblNameStep(int index){m_listLblNameStep.at(index)->setText(tr("Pas de cycle en cours"));};
	void razlblCurrentStep(int index){m_listLblCurrentStep.at(index)->setText("");};
public slots:
	void dataUpdate();
	void dataUpdateDiag();
private:
	void setConnexion();
	void init();
private:
	CWinMaintenanceModel* m_pModel;
	CWinMaintenanceControler* m_pControler;
	QTabWidget *m_tabWidgetCentral;

	//Tab Maintenance
	QList<QPushButton*> m_listBtExecuteCalib;
	QList<QPushButton*> m_listBtExecuteCalibInLine;
	QList<QPushButton*> m_listBtExecuteZero;
	QList<QPushButton*> m_listBtExecuteCleanup;

	QList<QLabel*> m_listLblCalib;
	QList<QLabel*> m_listLblCalibInLine;
	QList<QLabel*> m_listLblZero;
	QList<QLabel*> m_listLblCleanup;

	QList<QLabel*> m_listLblCurrentStep;
	QList<QLabel*> m_listLblTotalStep;
	QList<QLabel*> m_listLblNameStep;

    QLabel* m_lblCurrentStepDiag;
	QLabel* m_lblTotalStepDiag;
	QLabel* m_lblNameStepDiag;

	QList<QPushButton*> m_listBtStop;
	QPushButton* m_btBack;

	//tab diag
	QPushButton* m_btTemperatureCuve ;
	QPushButton* m_btPressionEau;
	QPushButton* m_btMesureOptique;
	QPushButton* m_btOpticalGain ;
	QPushButton* m_btOpticalMeasurement;
	QPushButton* m_btZeroOpticalMeasurement;

};
#endif
