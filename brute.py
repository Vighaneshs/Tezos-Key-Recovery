import hashlib
import bitcoin
import pysodium
from pyblake2 import blake2b
import unicodedata
import itertools
import time

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


#BRUTE FORCE
def brute(email, mnemonic, given_address):
    chSet = "abcdefghijklmnopqrstuvwxyz"
    min_pass = 1
    max_pass = 10
    
    for i in range(min_pass, max_pass):
        passSet = itertools.product(chSet, repeat = i)
        
        for pswrd in passSet:
            pswrd = "".join(pswrd)
            salt = unicodedata.normalize("NFKD", (email + pswrd))
            passW = "mnemonic" + salt
            passW = passW.encode("utf-8")
            nm = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
            seed = hashlib.pbkdf2_hmac("sha512", nm, passW, 2048)
            pk, sk = pysodium.crypto_sign_seed_keypair(seed[0:32])
            pkh1 = blake2b(pk,20).digest()
            if pkh1 == given_address:
                return pswrd
            

           
    

if __name__ == "__main__":
    email = "eg@email.com"
    password = "zzx"
    mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid"
    print("EMAIL:", email)
    print("MNEMONIC:", mnemonic)
    given_address = keygen(email,password,mnemonic)
    print("GIVEN ADDRESS/PUBLIC KEY HASH OF WALLET:", given_address)
    st = time.time()
    pswrd = brute(email,mnemonic, given_address)
    et = time.time()
    print(".....")
    print("password found:", pswrd)
    print("Brute Force time:",et-st, "s")
    print(".....")
