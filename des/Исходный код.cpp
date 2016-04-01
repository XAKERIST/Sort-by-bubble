/*#include<iostream>
using namespace std;
/*DWORD Decode3Des(BYTE* input, DWORD* szInput, BYTE* key1, BYTE* key2, BYTE* key3, BYTE* iVector)
{
HCRYPTPROV hProv;
CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)){

BLOBHEADER keyHeader;
keyHeader.bType = PLAINTEXTKEYBLOB;
keyHeader.bVersion = CUR_BLOB_VERSION;
keyHeader.reserved = 0;
keyHeader.aiKeyAlg = CALG_3DES;

BYTE bKey[36];
memset(bKey, 0, 36);
memcpy(bKey, &keyHeader, sizeof(keyHeader));
bKey[sizeof(keyHeader)] = 24;
memcpy(bKey + sizeof(keyHeader)+sizeof(DWORD), key1, 8);
memcpy(bKey + sizeof(keyHeader)+sizeof(DWORD)+8, key2, 8);
memcpy(bKey + sizeof(keyHeader)+sizeof(DWORD)+16, key3, 8);


DWORD result = 0;

HCRYPTKEY hKey;
if (CryptImportKey(hProv, bKey, sizeof(keyHeader)+sizeof(DWORD)+24, NULL, 0, &hKey)){

DWORD desMode = CRYPT_MODE_CBC;
CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&desMode, 0);

CryptSetKeyParam(hKey, KP_IV, iVector, 0);

if (CryptDecrypt(hKey, 0, TRUE, 0, input, szInput)) result = *szInput;


CryptDestroyKey(hKey);

}

CryptReleaseContext(hProv, 0);

return result;
}

return 0;
}*/

#include <locale>
#include <iostream>
#include <iomanip>
#include <string>
#include <Windows.h>
using namespace std;
int main()
{
	locale::global(locale("russian_russia.866"));
	// ������ ������ ��� ����������
	wcout << L"������� ������, ����� �� ������ �� �����������(secret):" << endl;
	wstring secret;
	getline(wcin, secret);
	// ����� ��� ������ ���������� ����������
	BYTE* buffer = 0;
	try
	{
		// ������ ������ � ������
		size_t strAllocSize = sizeof(wstring::value_type)*secret.length();
		// ������ ������ ������ ���� ������� ������
		size_t bufferSize = strAllocSize + 8;
		// �������� ������ ��� �����
		buffer = new BYTE[bufferSize];
#pragma warning(disable:4996)
		// �������� ������ � �����
		secret.copy(reinterpret_cast<wstring::value_type*>(buffer), secret.length(), 0);
#pragma warning(default:4996)
		// Crypto Sevice Provider
		HCRYPTPROV provider;
		// ���������� �������� CSP
		if (!CryptAcquireContext(&provider, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
		{
			throw L"�� ���������� �������� CSP";
		}
		// ���� ��� ����������
		HCRYPTKEY key;
		// ����������� ����
		if (!CryptGenKey(provider, CALG_3DES, CRYPT_EXPORTABLE, &key))
		{
			throw L"������ ��������� �����";
		}
		// ������������ �������� �����
		// ��� ������ ���� ��������� �� �����, �� ���� ���� �������
		// ������������ ������ ��� �� ���, �� ���� ���������
		// ���� ����� ��������������
		BYTE* keyBlob = 0;
		// ����� �����
		DWORD keyBlobLength = 0;
		// ������� ������ �����
		if (!CryptExportKey(key, 0, PLAINTEXTKEYBLOB, 0, 0, &keyBlobLength))
		{
			throw L"�� ���������� ��������� ����� �����";
		}
		// ������� ������ ��� �����
		keyBlob = new BYTE[keyBlobLength];
		// ������� �����
		if (!CryptExportKey(key, 0, PLAINTEXTKEYBLOB, 0, keyBlob, &keyBlobLength))
		{
			throw L"�� ���������� �������������� ����";
		}
		// ����������� ���
		wcout << endl << L"������������ ����(hex):" << endl;
		for (size_t i = 0; i<keyBlobLength; ++i)
		{
			wcout << hex << keyBlob[i];
		}
		wcout << endl;
		// ��������� ������ �� �������������
		delete[] keyBlob;
		// ������ ����� ������ ��� ����������
		DWORD dataSize = strAllocSize;
		// �������
		if (!CryptEncrypt(key, 0, true, 0, buffer, &dataSize, bufferSize))
		{
			throw L"����������� ������ �� �������";
		}
		// ����������� ��, ��� � ��� ����������
		wcout << endl << L"������������� ������(hex):" << endl;
		for (size_t i = 0; i<dataSize; ++i)
		{
			wcout << hex << buffer[i];
		}
		// ��������� ������������
		wcout << endl << endl
			<< L"��������� �� ������������:" << endl;
		if (!CryptDecrypt(key, 0, true, 0, buffer, &dataSize))
		{
			throw L"������������ ������ �� ����������";
		}
		// ������� �������������� ������
		wstring received(reinterpret_cast<wchar_t*>(buffer), reinterpret_cast<wchar_t*>(buffer + dataSize));
		wcout << L"�������������� ������(received):" << endl;
		wcout << received << endl;
		wcout << endl << L"�������� ��������� �� ������(���� � ��� ��� �����)" << endl
			<< L"(secret==received)=" << boolalpha << (secret == received) << endl;
	}
	catch (bad_alloc)
	{
		wcout << L"������ ��������� ������" << endl;
	}
	catch (const wchar_t* const msg)
	{
		wcout << L"����������:" << msg << endl;
	}
	if (buffer)
	{
		delete[] buffer;
	}
	system("PAUSE");
	return 0;
}