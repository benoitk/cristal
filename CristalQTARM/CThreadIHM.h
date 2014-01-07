#include <QThread>
class CListStream;
class CCarteIO;
class CCarteMesure;
class CSocketIHM;

class CThreadIHM : public QThread
{
	Q_OBJECT
public:
	CThreadIHM(int argc, char** argv, CListStream* argAnalyseur,CCarteIO* argCarteIO,CCarteMesure* argCarteMesure, CSocketIHM* argInterfaceIHM);
	~CThreadIHM(void);
	BOOL bGetInRunThread(){return m_bInRunThread;};
protected:
	virtual void run();

private:
	CListStream* m_Analyseur;
	CCarteIO* m_CarteIO;
	CCarteMesure* m_CarteMesure;
	CSocketIHM* m_InterfaceIHM;
	int m_argc;
	char** m_argv;
	bool m_bInRunThread;
};
