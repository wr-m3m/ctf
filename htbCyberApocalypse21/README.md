# HTB Cyber Apocalypse 2021
24.04.2021 

This is my first ever CTF I participated in. I don't have any significant experience in ctfs so I'm going to write my learnings down in this repository.

I focused on the Crypto challanges and was able to solve one and came close to solve another one. I didn't have all the time of the world, so I just had some fun on some evenings/early-mornings.

## PhaseStream1
### CHALLANGE

*The aliens are trying to build a secure cipher to encrypt all our games called "PhaseStream". They've heard that stream ciphers are pretty good. The aliens have learned of the XOR operation which is used to encrypt a plaintext with a key. They believe that XOR using a repeated 5-byte key is enough to build a strong stream cipher. Such silly aliens! Here's a flag they encrypted this way earlier. Can you decrypt it (hint: what's the flag format?) 2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904*

### SOLUTION
We know from the flag format that the first 5 bytes are **CHTB{**, this is our known plaintext -> crib.

The first 5 bytes from the ciphertext are **2e 31 3f 27 02**

XOR operation performed twice results in the original text, so we just have to XOR the crib **bytewise** and get the key. I struggled a bit with the bytewise aspect but after all It was quite easy. I used the very useful xor tool http://www.xor.pw/ but in the future I want to be able to use python and automate everything. I just had to be careful because the ciphertext was hex-encoded and the crib ASCII encoded, struggled a bit with encoding.

| C | H | T | B | { |
|---|---|---|---|---|
| 2e | 31 | 3f | 27 | 02 |
XOR 
| m | y | k | e | y |

Now the whole ciphertext can be decrypted with the found key (5byte) block by block. 
| 2e 31 3f 27 02 | 18 4c 5a 0b 1e | 32 12 05 55 0e | 03 26 1b 09 4d | 5c 17 1f 56 01 | 19 04 |
|---|---|---|---|---|---|
| m y k e y | m y k e y | m y k e y | m y k e y | m y k e y | m y |

### FLAG
CHTB{u51ng_kn0wn_pl41nt3xt}

## PhaseStream3

### CHALLANGE
*The aliens have learned the stupidity of their misunderstanding of Kerckhoffs's principle. Now they're going to use a well-known stream cipher (AES in CTR mode) with a strong key. And they'll happily give us poor humans the source because they're so confident it's secure!*

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

KEY = os.urandom(16)


def encrypt(plaintext):
    cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128))
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()


test = b"No right of private conversation was enumerated in the Constitution. I don't suppose it occurred to anyone at the time that it could be prevented."
print(encrypt(test))

with open('flag.txt', 'rb') as f:
    flag = f.read().strip()
print(encrypt(flag))
```
The provided output.txt file contains the following (without comments):
```
# test encrypted:
464851522838603926f4422a4ca6d81b02f351b454e6f968a324fcc77da30cf979eec57c8675de3bb92f6c21730607066226780a8d4539fcf67f9f5589d150a6c7867140b5a63de2971dc209f480c270882194f288167ed910b64cf627ea6392456fa1b648afd0b239b59652baedc595d4f87634cf7ec4262f8c9581d7f56dc6f836cfe696518ce434ef4616431d4d1b361c

# flag encrpted:
4b6f25623a2d3b3833a8405557e7e83257d360a054c2ea
```
### SOLUTION
Ok, so I know that AES in CTR mode has to be implemented correctly. Where the counter gets initialized I don't see a random IV getting passed in the function.
Maybe this is the vulnerability. If my theory is right, the keystream will be the same for both encrypted outputs (test, key) in output.txt. This mainly because it was encrypted in the same program run, because the key is the same. If this wasn't the case there would have been a key change and I wouldn't be able to crack it.
```
            CTR + IV                    CTR + (IV+1)
                |                           |
                v                           v
            |-------|                   |-------|
Key(16) --> |  AES  |       Key(16) --> |  AES  |
            |-------|                   |-------|
                |                           |
                v                           v
Plaintext --> (xor)         Plaintext --> (xor)
                |                           |
                v                           v
                C                           C
```
Ciphertext (C) is simply the Plaintext XORed with the Keystream generated from AES(16 byte blocks).

**KnownPlaintextCiphertext xor KnownPlaintext = KEY**

```
            CTR + IV             
                |                    
                v                        
            |-------|                
Key(16) --> |  AES  |     
            |-------|     KEY              
                |          ^             
                v          |               
Plaintext --> (xor)      (xor) <-- Plaintext
                |          ^                 
                v          |                   
                C          C                  
```

**KEY xor FlagCiphertext = FlagPlaintext**

I wasn't able to code the "encrypter", but after checking writeups I saw that I was right and almost hat the flag.

## Final thoughts
Encoding is tricky sometimes. I can use the python CTF toolkit [pwntools](https://github.com/Gallopsled/pwntools) to xor.