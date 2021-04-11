import sys,binascii
from Crypto.Cipher import AES

def removepadding(plaintext):
    return (int.from_bytes(plaintext[-1][-1:], "big"))
    
    

def xor(c,d):
    return (bytes(a ^ b for (a,b) in zip (c,d)))

def decryptAES(key, IV, CT):
    plaintext=[]
    length= int(int(len(CT)/16))
    cipher = AES.new(key,AES.MODE_ECB)
    for i in range (0,len(CT),16):
        if i==0:
            plaintext.append(xor((cipher.decrypt(CT[i:i+16])),IV))
        else:
            plaintext.append(xor((cipher.decrypt(CT[i:i+16])),CT[i-16:i]))
    paddingint=removepadding(plaintext)
    plaintextcomb=b''.join(plaintext)
    print (plaintextcomb[:-paddingint])
    
    

def decrypt(key, ciphertext):
    CT=binascii.unhexlify(ciphertext)
    key=binascii.unhexlify(key)
    IV=CT[:16]
    CT=CT[16:]
    decryptAES(key, IV, CT)

def main():
    Key=["140b41b22a29beb4061bda66b6747e14", "140b41b22a29beb4061bda66b6747e14"]
    CT=["4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81", "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"]
    for k in range (len(CT)):
        decrypt(Key[k],CT[k])

if __name__ == "__main__":
    main()
