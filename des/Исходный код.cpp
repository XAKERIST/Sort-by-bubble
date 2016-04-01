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
	// Введем строку для шифрования
	wcout << L"Введите строку, какую Вы хотели бы зашифровать(secret):" << endl;
	wstring secret;
	getline(wcin, secret);
	// Буфер для работы алгоритмов шифрования
	BYTE* buffer = 0;
	try
	{
		// Размер строки в памяти
		size_t strAllocSize = sizeof(wstring::value_type)*secret.length();
		// Размер буфера должен быть немного больше
		size_t bufferSize = strAllocSize + 8;
		// Выделяем память под буфер
		buffer = new BYTE[bufferSize];
#pragma warning(disable:4996)
		// Копируем строку в буфер
		secret.copy(reinterpret_cast<wstring::value_type*>(buffer), secret.length(), 0);
#pragma warning(default:4996)
		// Crypto Sevice Provider
		HCRYPTPROV provider;
		// Попытаемся получить CSP
		if (!CryptAcquireContext(&provider, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
		{
			throw L"Не получилось получить CSP";
		}
		// Ключ для шифрования
		HCRYPTKEY key;
		// Сгенерируем ключ
		if (!CryptGenKey(provider, CALG_3DES, CRYPT_EXPORTABLE, &key))
		{
			throw L"Ошибка генерации ключа";
		}
		// Демонстрация экспорта ключа
		// Для работы этой программы не нужна, но если есть желание
		// расшифровать данные где то еще, то ключ необходим
		// Сюда будем экспортировать
		BYTE* keyBlob = 0;
		// Длина ключа
		DWORD keyBlobLength = 0;
		// Получим размер ключа
		if (!CryptExportKey(key, 0, PLAINTEXTKEYBLOB, 0, 0, &keyBlobLength))
		{
			throw L"Не получилось вычислить длину ключа";
		}
		// Выделим память для ключа
		keyBlob = new BYTE[keyBlobLength];
		// Экспорт ключа
		if (!CryptExportKey(key, 0, PLAINTEXTKEYBLOB, 0, keyBlob, &keyBlobLength))
		{
			throw L"Не получилось экспортировать ключ";
		}
		// Распечатаем его
		wcout << endl << L"Сгенерирован ключ(hex):" << endl;
		for (size_t i = 0; i<keyBlobLength; ++i)
		{
			wcout << hex << keyBlob[i];
		}
		wcout << endl;
		// Освободим память за ненадобностью
		delete[] keyBlob;
		// Размер наших данных для шифрования
		DWORD dataSize = strAllocSize;
		// Шифруем
		if (!CryptEncrypt(key, 0, true, 0, buffer, &dataSize, bufferSize))
		{
			throw L"Зашифровать данные не удалось";
		}
		// Распечатаем то, что у нас получилось
		wcout << endl << L"Зашифрованная строка(hex):" << endl;
		for (size_t i = 0; i<dataSize; ++i)
		{
			wcout << hex << buffer[i];
		}
		// Попробуем расшифровать
		wcout << endl << endl
			<< L"Попробуем ее расшифровать:" << endl;
		if (!CryptDecrypt(key, 0, true, 0, buffer, &dataSize))
		{
			throw L"Расшифровать данные не получилось";
		}
		// Соберем результирующую строку
		wstring received(reinterpret_cast<wchar_t*>(buffer), reinterpret_cast<wchar_t*>(buffer + dataSize));
		wcout << L"Расшифрованные данные(received):" << endl;
		wcout << received << endl;
		wcout << endl << L"Проверим совпадают ли строки(хотя и так это видно)" << endl
			<< L"(secret==received)=" << boolalpha << (secret == received) << endl;
	}
	catch (bad_alloc)
	{
		wcout << L"Ошибка выделения памяти" << endl;
	}
	catch (const wchar_t* const msg)
	{
		wcout << L"Исключение:" << msg << endl;
	}
	if (buffer)
	{
		delete[] buffer;
	}
	system("PAUSE");
	return 0;
}