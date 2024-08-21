# Encrypt the message "the house is being sold tonight" using one of the following ciphers. 
# Ignore the space between words. Decrypt the message to get the original plaintext:
# • Vigenere cipher with key: "dollars"
# • Autokey cipher with key = 7
Plain_Text="the house is being sold tonight"
def Vignere(P,k):
    Cipher_text=""
    index=0
    k=k*int(len(P)/len(k)+1)
    for char in P:
        if(char.isalpha()):
            n=ord(char)
            to_add=ord(k[index])-ord('a')
            index+=1
            if(char.islower()):
                n+=to_add
                if(n>ord('z')):
                    n-=26
            else:
                n+=to_add
                if(n>ord('Z')):
                    n-=26
            Cipher_text+=chr(n)
        else:
            Cipher_text+=char
    Cipher_text=Cipher_text.replace(" ","")
    return Cipher_text
def vignere_decode(P,k):
    Cipher_text=""
    index=0
    k=k*int(len(P)//len(k)+1)
    for char in P:
        if(char.isalpha()):
            n=ord(char)
            to_add=ord(k[index])-ord('a')
            index+=1
            if(char.islower()):
                n-=to_add
                if(n<ord('a')):
                    n+=26
            else:
                n-=to_add
                if(n<ord('A')):
                    n+=26
            Cipher_text+=chr(n)
        else:
            Cipher_text+=char
    print(Cipher_text)

def autokey(P,key):
    if(P[0].islower()):
        add='a'
    else:
        add='A'
    k=chr(key+ord(add))+P
    k=k.replace(" ", "")
    return (Vignere(P,k))
    
def autokey_decode(P,key):
    if(P[0].islower()):
        add='a'
    else:
        add='A'
    plain_Text=""
    k=chr(key+ord(add)) #k is the current decoding key
    for i in range(len(P)):
        if(P[i].islower()):
            add='a'
        else:
            add='A'
        j=ord(k)-ord(add) #spaces to be decreased
        curr=ord(P[i])-j
        if(add=='a' and curr<ord('a')):
            curr+=26
        if(add=='A' and curr<ord('A')):
            curr+=26
        k=chr(curr)
        plain_Text=plain_Text+k
        
    print(plain_Text)
        
            
        
        
        
        
        
    

print("Plain Text:",Plain_Text)
print("\nVignere Cipher with Key=dollars:")
a=Vignere(Plain_Text,"dollars")
print("Encoded:")
print(a)
print("Decoded:")
vignere_decode(a,"dollars")
print("\nAutoKey Cipher with Key=7:")
a=autokey(Plain_Text,7)
print("Encoded:")
print(a)
print("Decoded:")
autokey_decode(a,7)
