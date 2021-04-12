import sys,binascii
from Crypto.Cipher import AES

def removepadding(plaintext):
    return (int.from_bytes(plaintext[-1][-1:], "big"))
    
    

def xor(c,d):
    return (bytes(a ^ b for (a,b) in zip (c,d)))

def decryptAESCBC(key, IV, CT):
    plaintext=[]
    length= int(int(len(CT)/16))
    cipher = AES.new(key,AES.MODE_ECB) # we use ECB as we just want to one block at a time
    for i in range (0,len(CT),16):
        if i==0:
            plaintext.append(xor((cipher.decrypt(CT[i:i+16])),IV))
        else:
            plaintext.append(xor((cipher.decrypt(CT[i:i+16])),CT[i-16:i]))
    paddingint=removepadding(plaintext)
    plaintextcomb=b''.join(plaintext)
    print (plaintextcomb[:-paddingint])

def decryptAESCTR(key, IV, CT):
    length= int(int(len(CT)/16))
    cipher = AES.new(key,AES.MODE_ECB)
    plaintext=[]
    for i in range (0,len(CT),16):
        plaintext.append(xor((cipher.encrypt(IV)),CT[i:i+16]))
        IVplusone = int.from_bytes(IV, 'big') +1 ## this is incrementing the byte by one as an int
        IV=bytearray(IVplusone.to_bytes(16, 'big')) ## and converitn it back
    plaintextcomb=b''.join(plaintext)
    print (plaintextcomb)
    
    

def decrypt(key, ciphertext):
    CT=binascii.unhexlify(ciphertext)
    key=binascii.unhexlify(key)
    IV=CT[:16]
    CT=CT[16:]
    decryptAESCBC(key, IV, CT)

def decryptCTR(key, ciphertext):
    CT=binascii.unhexlify(ciphertext)
    key=binascii.unhexlify(key)
    IV=CT[:16]
    CT=CT[16:]
    decryptAESCTR(key, IV, CT)

def main():
    Key=["140b41b22a29beb4061bda66b6747e14", "140b41b22a29beb4061bda66b6747e14"]
    CT=["4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81", "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"]
    KeyCTR=["36f18357be4dbd77f050515c73fcf9f2", "36f18357be4dbd77f050515c73fcf9f2"]
    CT_CTR=["69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329", "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"]
    for k in range (len(CT)):
        decrypt(Key[k],CT[k])
    for k in range (len(CT_CTR)):
        decryptCTR(KeyCTR[k],CT_CTR[k])

if __name__ == "__main__":
    main()
