

#pragma once

class CSystem
{
	public:
		static BOOL getModelInformation(TCHAR* buf, UINT bufLength);
		static BOOL getSerialNumber(TCHAR* buf, UINT bufLength);
		static BOOL HardResetPanelPC() ;

};