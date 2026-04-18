#include <windows.h>

bool ExecuteViaAPC(HANDLE hThread, PVOID pEntryPoint) {
    // Queue the DLL entry point to the thread's APC queue
    // When the thread sleeps or waits, it will execute our DLL
    if (!QueueUserAPC((PAPCFUNC)pEntryPoint, hThread, NULL)) {
        return false;
    }
    return true;
}
