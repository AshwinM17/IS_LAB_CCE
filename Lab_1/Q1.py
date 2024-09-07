# Encrypt the message "I am learning information security" using one of the following ciphers. 
# Ignore the space between words. Decrypt the message to get the original plaintext:
# a) Additive cipher with key = 20
# b) Multiplicative cipher with key = 15
# c) Affine cipher with key = (15, 20)
Plain_text="I am learning information security"

def additive_ciphers(P,k):
    shifted_text = ""
    for char in P:
        if char.isalpha():  
            n = ord(char) + k
            # Wrap around if it goes beyond 'z' or 'Z'
            if char.islower() and n > ord('z'):
                n -= 26
            elif char.isupper() and n > ord('Z'):
                n -= 26
            shifted_text += chr(n)
        else:
            shifted_text += char  # Leave non-alphabetic characters unchanged
    return(shifted_text)
def additive_decode(P,k):
    shifted_text = ""
    for char in P:
        if char.isalpha():  
            n = ord(char) - k
            # Wrap around if it goes beyond 'z' or 'Z'
            if char.islower() and n < ord('a'):
                n += 26
            elif char.isupper() and n < ord('A'):
                n += 26
            shifted_text += chr(n)
        else:
            shifted_text += char  # Leave non-alphabetic characters unchanged
    print(shifted_text)
def multiplicative(P,k):
    Cipher_text=""
    for char in P:
        if char.isalpha():
            if(char.islower()):
                minus=ord('a')
                n=(ord(char)-minus)*k
                n%=26
            else:
                minus=ord('A')
                n=(ord(char)-minus)*k
                n%=26
            Cipher_text+=chr(n+minus)
        else:
            Cipher_text+=char 
    return Cipher_text
def multiplicative_decode(P,key):
    try:
        k=pow(key,-1,26)
    except:
        print("Inverse Doesn't exist so can't be decoded")
        return
    print(multiplicative(P,k))
    
def Affine_Cipher(P,k1,k2):
    Cipher_text=""
    for char in P:
        if char.isalpha():
            if(char.islower()):
                minus=ord('a')
                n=(ord(char)-minus)*k1
                n+=k2
                n%=26
            else:
                minus=ord('A')
                n=(ord(char)-minus)*k1
                n+=k2
                n%=26
            Cipher_text+=chr(n+minus)
        else:
            Cipher_text+=char 
    return Cipher_text

def Affine_decode(P,k1,k2):
    try:
        k1=pow(k1,-1,26)
    except:
        print("Inverse Doesn't exist so can't be decoded")
        return
    Cipher_text=""
    for char in P:
        if char.isalpha():
            if(char.islower()):
                minus=ord('a')
                n=ord(char)-k2
                if(n<ord('a')):
                    n+=26
                n=(n-minus)*k1
                n%=26
            else:
                minus=ord('A')
                n=ord(char)-k2
                if(n<ord('A')):
                    n+=26
                n=(n-minus)*k1
                n%=26
            Cipher_text+=chr(n+minus)
        else:
            Cipher_text+=char 
    print(Cipher_text)
    
print("PlainText: I am learning information security\n")
print("Additive Cipher with Key=20:")
a=additive_ciphers(Plain_text,20)
print("Encoded:")
print(a)
print("Decoded:")
additive_decode(a,20)

a=multiplicative(Plain_text,15)
print("\nMultiplicative Cipher with Key=15:")
print("Encoded:")
print(a)
print("Decoded:")
multiplicative_decode(a,15)

a=Affine_Cipher(Plain_text,15,20)
print("\nAffine Cipher with Key1=15 and Key2=20:")
print("Encoded:")
print(a)
print("Decoded:")
Affine_decode(a,15,20)

print(additive_ciphers("HELLO BRO",1))