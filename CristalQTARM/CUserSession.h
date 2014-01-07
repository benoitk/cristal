#ifndef CUSER_SESSION
#define CUSER_SESSION

#include <QObject>
#include <QList>
class QTimer;
class InterfaceUserSession;

class CUserSession : public QObject
{
	Q_OBJECT
public:
	static CUserSession* getInstance();
	
	int getUserType()const{return m_nUserType;};
	bool loginAdmin(bool arg_bAutoLogin=false);
	bool loginUser(bool arg_bAutoLogin=false);
    bool loginAsLastUser(bool arg_bAutoLogin=false);
	bool amIGuest()const;
	bool amIAdmin()const;
	bool amIUser()const;
	
	void objectRegister(InterfaceUserSession* pObject);
	void objectUnregister(InterfaceUserSession* pObject);
public slots:
	void logout();
	void poke();
private:
	int login(const QString& sPwd);	
	CUserSession(void);
	static CUserSession* singleton;
	QList<InterfaceUserSession*> m_listObjectRegistered;

	int m_nUserType;
	int m_nLastUserType;
	QTimer* m_timer;

};

#endif CUSER_SESSION
