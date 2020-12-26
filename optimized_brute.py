import hashlib
import bitcoin
import pysodium
from pyblake2 import blake2b
import unicodedata
import itertools
import time
import threading

#KEY GENERATION
def keygen(email, password, mnemonic):
    salt = unicodedata.normalize("NFKD", (email + password))
    passW = "mnemonic" + salt
    passW = passW.encode("utf-8")
    nm = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    seed = hashlib.pbkdf2_hmac("sha512", nm, passW, 2048)
    pk, sk = pysodium.crypto_sign_seed_keypair(seed[0:32])
    pkh = blake2b(pk,20).digest()
    given_address = pkh
    return given_address


#PRECOMPUTATION
def precomp(email, mnemonic):
    chSet = "abcdefghijklmnopqrstuvwxyz"
    min_pass = 1
    max_pass = 4
    pList = []
    for i in range(min_pass, max_pass):
        passSet = itertools.product(chSet, repeat = i)
        for pswrd in passSet:
            pswrd = "".join(pswrd)
            pList.append(pswrd)
            
    return pList


#BRUTE FORCE
def brute(email, mnemonic, given_address, pList):
    for pswrd in pList:
        salt = unicodedata.normalize("NFKD", (email + pswrd))
        passW = "mnemonic" + salt
        passW = passW.encode("utf-8")
        nm = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
        seed = hashlib.pbkdf2_hmac("sha512", nm, passW, 2048)
        pk, sk = pysodium.crypto_sign_seed_keypair(seed[0:32])
        pkh1 = blake2b(pk,20).digest()
        if pkh1 == given_address:
            print("password found:",pswrd)
            return pswrd
    return 
    

if __name__ == "__main__":
    email = "eg@email.com"
    password = "zzx"
    mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid"

    print("EMAIL:", email)
    print("MNEMONIC:", mnemonic)
    given_address = keygen(email,password,mnemonic)
    print("GIVEN ADDRESS/PUBLIC KEY HASH OF WALLET:", given_address)
    print("....")
    pList = precomp(email, mnemonic)
    nT = 12
    chunkSize = len(pList)//nT + 1
    chunks = [pList[i:i+chunkSize] for i in range(0, len(pList), chunkSize)]
    
    #MULTI THREADING
    threads = []
    st = time.time()
    for i in range(nT):
        t = threading.Thread(target =brute, args = (email,mnemonic, given_address, chunks[i],))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
        
    et = time.time()
    print("Brute Force time:",et-st, "s")
    print("....")