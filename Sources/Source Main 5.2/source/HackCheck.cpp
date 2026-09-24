#include "stdafx.h"
#include "HackCheck.h"

CHackCheck gHackCheck;

void CHackCheck::Init()
{
	WORD EncDecKey = 0;

	char CustomerName[32] = "Alejandro";
	char ClientSerial[17] = "TbYehR2hFUPBKgZj";

	for (int n = 0; n < sizeof(CustomerName); n++)
	{
		EncDecKey += (BYTE)(
			CustomerName[n] ^
			ClientSerial[n % sizeof(ClientSerial)]
			);

		EncDecKey ^= (BYTE)(
			CustomerName[n] -
			ClientSerial[n % sizeof(ClientSerial)]
			);
	}

	this->EncDecKey1 = (BYTE)0xB0;
	this->EncDecKey2 = (BYTE)0xF8;

	this->EncDecKey1 = (BYTE)(
		this->EncDecKey1 + LOBYTE(EncDecKey)
		);

	this->EncDecKey2 = (BYTE)(
		this->EncDecKey2 + HIBYTE(EncDecKey)
		);
}

int WINAPI CHackCheck::MyRecv(SOCKET s, BYTE* buf, int len, int flags)
{
	int result = gHackCheck.HookRecv(s, buf, len, flags);

	if (result == SOCKET_ERROR || result == 0)
	{
		return result;
	}

	if (gHackCheck.CheckSocketPort(s))
	{
		gHackCheck.DecryptData(buf, result);
	}

	return result;
}

int WINAPI CHackCheck::MySend(SOCKET s, BYTE* buf, int len, int flags)
{
	if (gHackCheck.CheckSocketPort(s))
	{
		gHackCheck.EncryptData(buf, len);
	}

	return gHackCheck.HookSend(s, buf, len, flags);
}

bool CHackCheck::CheckSocketPort(SOCKET s)
{
	SOCKADDR_IN addr;

	int addr_len = sizeof(addr);

	if (getpeername(s, (SOCKADDR*)&addr, &addr_len) == SOCKET_ERROR)
	{
		return false;
	}

	if (PORT_RANGE(ntohs(addr.sin_port)) == 0)
	{
		return false;
	}

	return true;
}

void CHackCheck::DecryptData(BYTE* lpMsg, int size)
{
	for (int n = 0; n < size; n++)
	{
		int value =
			((int)lpMsg[n] ^ (int)this->EncDecKey1)
			-
			((int)this->EncDecKey2 * (int)this->EncDecKey1);

		lpMsg[n] = (BYTE)(value & 0xFF);
	}
}

void CHackCheck::EncryptData(BYTE* lpMsg, int size)
{
	for (int n = 0; n < size; n++)
	{
		int value =
			((int)lpMsg[n] +
				((int)this->EncDecKey2 * (int)this->EncDecKey1))
			^
			(int)this->EncDecKey1;

		lpMsg[n] = (BYTE)(value & 0xFF);
	}
}