'''
Implemtation of the RC4 algorithm as based on the wikipedia for RC4

-----------FOR KSA ---------

for i from 0 to 255
    S[i] := i
endfor
j := 0
for i from 0 to 255
    j := (j + S[i] + key[i mod keylength]) mod 256
    swap values of S[i] and S[j]
endfor

-----------FOR GENERATING STREAM--------------

i := 0
j := 0
while GeneratingOutput:
    i := (i + 1) mod 256
    j := (j + S[i]) mod 256
    swap values of S[i] and S[j]
    K := S[(S[i] + S[j]) mod 256]
    output K
endwhile

'''

def KSA(key):
    key_length = len(key)
    S = [i for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i],S[j] = S[j],S[j]
    return S    

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i],S[j] = S[j],S[j]
        K = S[(S[i] + S[j]) % 256]
        yield(K)   

def convert_key(key_in_bits):
    key_length = len(key_in_bits)
    key_in_bytes = []
    for i in range(0,key_length-7,8):
        byte = key_in_bits[i:i+8]
        val = int("".join(str(x) for x in byte),2)
        key_in_bytes.append(val)
    return key_in_bytes

def RC4(key_in_bits):
    key_in_bytes = convert_key(key_in_bits)
    S = KSA(key_in_bytes)
    return PRGA(S)