#include "CUserSession.h"
#include "InterfaceUserSession.h"
#include "CDialogPassword.h"
#include "header_qt.h"

#define USER_CODE  "0712"
#define ADMIN_CODE "2508"
#define GUEST 0
#define USER 1
#define ADMIN 2

CUserSession* CUserSession::singleton = 0;
CUserSession::CUserSession(void)
{
	m_nUserType = GUEST;
    m_nLastUserType = GUEST;
	m_timer = new QTimer(this);
	m_timer->setInterval(600000);
}

CUserSession* CUserSession::getInstance()
{
	if(!singleton)
			singleton = new CUserSession();
	return singleton;
}

int CUserSession::login(const QString& sPwd)
{
	qDebug() << "LOGIN ATTEMPT" << endl;
	if(sPwd == USER_CODE)
	{
		qDebug() << "LOGIN USER";
		m_timer->start();	
		return m_nUserType=USER;
	}
	else if(sPwd == ADMIN_CODE)
	{
		qDebug() << "LOGIN ADMIN";
		m_timer->start();
		return m_nUserType=ADMIN;
	}
	else
		return m_nUserType=GUEST;
}

//SLOT
void CUserSession::logout()
{
	qDebug() << "LOGOUT";
    m_nLastUserType = m_nUserType;
	m_nUserType = GUEST;
	
} 

//SLOT
void CUserSession::poke()
{
	if(!amIGuest())
	{
		m_timer->start();
		qDebug() << "POKE POKE POKE" << endl;
	}
}

void CUserSession::objectRegister(InterfaceUserSession* pObject)
{
	m_listObjectRegistered.append(pObject);
	disconnect(m_timer, 0,0,0);
	connect(m_timer, SIGNAL(timeout()), this, SLOT(logout()));
	connect(m_timer, SIGNAL(timeout()), pObject, SLOT(userSessionClosed()));
}

void CUserSession::objectUnregister(InterfaceUserSession* pObject)
{
	m_listObjectRegistered.removeOne(pObject);
	disconnect(m_timer, 0,0,0); 
	if(!m_listObjectRegistered.isEmpty())
	{
		connect(m_timer, SIGNAL(timeout()), this, SLOT(logout()));
		connect(m_timer, SIGNAL(timeout()), m_listObjectRegistered.first(), SLOT(userSessionClosed()));
	}
}

bool CUserSession::loginAdmin(bool arg_bAutoLogin)
{
	qDebug() << "CUserSession::loginAdmin(bool arg_bAutoLogin)" << arg_bAutoLogin << endl;
	if(m_nUserType == ADMIN)
		return true;
	else
	{
		
		CDialogPassword::getInstance()->setPassordToCheck(ADMIN_CODE);
		if(arg_bAutoLogin || CDialogPassword::getInstance()->exec())
			return login(ADMIN_CODE);
		else
			return false;
	}
}
bool CUserSession::loginUser(bool arg_bAutoLogin)
{
	if(m_nUserType == USER || m_nUserType == ADMIN)
		return true;
	else
	{
		CDialogPassword::getInstance()->setPassordToCheck(USER_CODE, ADMIN_CODE);
		if(arg_bAutoLogin ||CDialogPassword::getInstance()->exec())
			return login(CDialogPassword::getInstance()->getPasswordChecked());
		else
			return false;
	}
}
bool CUserSession::loginAsLastUser(bool arg_bAutoLogin)
{
	QString userCode;
	switch(m_nLastUserType)
    {
    case USER :
        userCode = USER_CODE;
		break;
	case ADMIN :
        userCode = ADMIN_CODE;
		break;
    }

	CDialogPassword::getInstance()->setPassordToCheck(userCode, ADMIN_CODE);
	if(arg_bAutoLogin)
		return login(CDialogPassword::getInstance()->getPasswordChecked());
	else if(CDialogPassword::getInstance()->exec())
		return login(CDialogPassword::getInstance()->getPasswordChecked());
	else
		return false;
}

bool CUserSession::amIGuest()const
{
	if(m_nUserType == GUEST)
		return true;
	else
		return false;
}
bool CUserSession::amIAdmin()const
{
	if(m_nUserType == ADMIN)
		return true;
	else
		return false;
}
bool CUserSession::amIUser()const
{
	if(m_nUserType == USER)
		return true;
	else
		return false;
}