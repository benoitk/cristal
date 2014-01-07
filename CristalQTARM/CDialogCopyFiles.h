#ifndef CDIALOG_COPY_FILES
#define CDIALOG_COPY_FILES

#include <QDialog>
#include <QProgressBar>

class QDir;
class QLabel;
class QPushButton;

class CDialogCopyFiles: public QDialog
{
	Q_OBJECT
public:
	static CDialogCopyFiles* getInstance();
	void setConnexion();

public slots:
	void execCopy();
	void resetDialog();
private:
	CDialogCopyFiles();
	QPushButton* m_btBack;
	QPushButton* m_btApply;
	static CDialogCopyFiles* singleton;

	QDir* m_logErrorPrgFileDir;
	QDir* m_logFileDir;
	QDir* m_logUserFileDir;
	QProgressBar m_progressBar;
	QLabel* m_lblInfo;

};
#endif //CDIALOG_COPY_FILES