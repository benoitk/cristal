#ifndef CDIALOG_CONFIGSEUIL_H
#define CDIALOG_CONFIGSEUIL_H

#include <QDialog>
#include <QString>
class QLabel;
class QLineEdit;
class QPushButton;
class QTabWidget;

class CDialogConfigSeuil : public QDialog
{
	Q_OBJECT

public:
	static CDialogConfigSeuil* getInstance();

	void setValueName(const QString& sNameValue);
	void setValue(int arg_numConfig);
	int getValue();

    void setNbStreamEnabled(int arg_nbStream);
public slots:
	
	void btHautHautPressed();
	void btBasBasPressed();
	void btBasHautPressed();
		
private:
	CDialogConfigSeuil();
	void setConnexion();
	void changeValue(int arg_numConfig);
public:
	
private:
	static CDialogConfigSeuil* singleton;
	QString m_sNameValue;
	QString m_sValue;
	QString m_sValueMax;
	QString m_sValueMin;
	QString m_sValueUnit;

	float m_fValue;

	QLabel* m_lblNameValue;
	QLineEdit* m_lblValue;
    int m_nValue;
	QLabel* m_lblNameSeuil1;
	QLabel* m_lblValueSeuil1;
	QLabel* m_lblNameSeuil2;
	QLabel* m_lblValueSeuil2;

	QPushButton* m_btHautHaut;
	QPushButton* m_btBasBas;
	QPushButton* m_btBasHaut;
	
	QPushButton* m_btBack;
	QPushButton* m_btApply;
		
	QTabWidget* m_tabWidget;



};

#endif // CDIALOGPAVENUM_H
