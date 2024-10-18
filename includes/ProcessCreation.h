#ifndef PAYLOADINJECTION_H
#define PAYLOADINJECTION_H

#include <windows.h>

BOOL InjectPayload(HANDLE hProcess, LPVOID lpPayload, SIZE_T payloadSize);
BOOL QueuePayloadAPC(HANDLE hThread, LPVOID lpPayloadBase);

#endif
