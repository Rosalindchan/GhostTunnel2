#pragma once
#include"stdafx.h"

class mainProcess
{
private:
	HANDLE hClient;//ָ��wlan�ͻ����ڻỰ��ʹ�õľ������������ᴩ�����Ự����������ʹ��
	PWLAN_INTERFACE_INFO_LIST pIfList;//ָ��洢 ���ؼ�������õ�����LAN�ӿ� ��ָ��
	PWLAN_INTERFACE_INFO pIfInfo;//������Ϣ
	PWLAN_AVAILABLE_NETWORK_LIST pBssList; //����������Ϣ�б�
	WLAN_AVAILABLE_NETWORK* pBssEntry;
	char *sendInfo;
	char *hash;
public:
	mainProcess();
	~mainProcess();
	DWORD get_Handle(HANDLE *hClient, DWORD dwMaxClient, DWORD dwCurVersion);
	DWORD get_WlanList(HANDLE *hClient, PWLAN_INTERFACE_INFO_LIST *pIfList);
	PWLAN_INTERFACE_INFO get_Wlan(PWLAN_INTERFACE_INFO_LIST *pIfList);
	DWORD sendRequest(HANDLE *hClient, PWLAN_INTERFACE_INFO *pIfInfo, PWLAN_RAW_DATA pwlan_data);
	boolean getssid(HANDLE *hClient, PWLAN_INTERFACE_INFO *pIfInfo, char *ssid);
	PWLAN_RAW_DATA get_payload(char *buf);
	void run();
	char *get_sendInfo();
	void set_sendInfo(char* infomation);
	char *get_hash();
	void set_hash(char* hash);
};

