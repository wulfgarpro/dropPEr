# dropPEr

My solution to the final assignment for
[SEKTOR7's RED TEAM Operator: Malware Development Essentials Course](https://institute.sektor7.net/red-team-operator-malware-development-essentials).

`dropPEr` is a Windows dropper that:

* encrypts the payload with AES;
* encrypts all strings with AES;
* obfuscates all function calls.

The payload `msgbox.bin` was generated using `msfvenom`:

```shell
msfvenom -p windows/x64/messagebox TEXT="Hello, World!" TITLE="Welcome" EXITFUNC=thread -f raw -o msgbox64.bin
```

## Building & Run

From an x64 Native Tools Command Prompt for VS, run:

```sh
compile.bat
.\d0.exe
```

Observe the message box demonstrating code execution.

## How it works...

XXX

