#ifndef PAYLOADINJECTION_H
#define PAYLOADINJECTION_H

#include <windows.h>

LPVOID InjectPayload(HANDLE hProcess, LPVOID lpPayload, SIZE_T payloadSize);
BOOL QueuePayloadAPC(HANDLE hThread, LPVOID lpPayloadBase);

#endif
