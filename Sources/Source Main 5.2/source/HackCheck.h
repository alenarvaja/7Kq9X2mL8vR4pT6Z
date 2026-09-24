#pragma once

#define MIN_PORT 55901
#define MAX_PORT 55950

#define PORT_RANGE(x) (((x) < MIN_PORT) ? 0 : ((x) > MAX_PORT) ? 0 : 1)

class CHackCheck
{
public:
	void Init();

	bool CheckSocketPort(SOCKET s);

	void DecryptData(BYTE* lpMsg, int size);

	void EncryptData(BYTE* lpMsg, int size);

private:
	BYTE EncDecKey1;
	BYTE EncDecKey2;
};

extern CHackCheck gHackCheck;