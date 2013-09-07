#!/usr/bin/python
 
# Hashing Script which generates hashes from plaintext strings, and allows you to
# compare a string with a hash to determine if you have the correct cleartext string

# Author: Christopher Truncer
# Thanks for the help with stupid errors I couldn't solve from those who don't want to be named!
 
import os
import passlib.hash as hashes
import hashlib
 
def printTitle():
    os.system("clear")
    print "##############################################################################"
    print "#                                Hasher v1.0                                 #"
    print "##############################################################################\n"
 
def printorCheck():
    print "Hasher generates hashes, or compare a plaintext string with a hash."
    print "Which would you like to do?\n"
    print "Menu Options: \n"
    print "1 - Generate Hash"
    print "2 - Compare Plaintext String with Hash\n"
    functionselection = raw_input("Option Number: ")
    if functionselection == "1":
        functionselection = "generate"
    else:
        functionselection = "compare"
    return functionselection
 
def supportedHashes():
    print "The following is a list of hashing algorithms Hasher currently supports:\n"
    print "1 - MD5"
    print "2 - SHA1"
    print "3 - SHA256"
    print "4 - SHA512"
    print "5 - NTLM"
    print "6 - MS Domain Cached"
    print "7 - MS Domain Cached v2"
    print "8 - MD5 Crypt"
    print "9 - SHA1 Crypt"
    print "10 - SHA256 Crypt\n"
    print "Which hashing algorithm would you like to work with?"
    hashselection = raw_input("Option Number: ")
    if hashselection == "1":
        hashselection = "md5"
        return hashselection
    elif hashselection == "2":
        hashselection = "sha1"
        return hashselection
    elif hashselection == "3":
        hashselection = "sha256"
        return hashselection
    elif hashselection == "4":
        hashselection = "sha512"
        return hashselection
    elif hashselection == "5":
        hashselection = "NTLM"
        return hashselection
    elif hashselection == "6":
        hashselection = "msdcc"
        return hashselection
    elif hashselection == "7":
        hashselection = "msdcc2"
        return hashselection
    elif hashselection == "8":
        hashselection = "md5_crypt"
        return hashselection
    elif hashselection == "9":
        hashselection = "sha1_crypt"
        return hashselection
    elif hashselection == "10":
        hashselection = "sha256_crypt"
        return hashselection
    else:
        "This will now error because you didn't provide a valid selection, and I didn't implement error checking yet"
    return hashselection
 
def getPlaintext(menuchoice):
    if menuchoice == "1":
        print "Please provide the plaintext string you want to hash\n"
    else:
        print "Please provide the plaintext string you wish to compare to a hash\n"
    userstring = raw_input("Plaintext String: ")
    return userstring
 
def getHash():
    print "Please provide the hash you want to compare with your plaintext string"
    userhash = raw_input("Hash: ")
    return userhash

def roundGather():
    print "How many rounds of hashing would you like?"
    rounds = raw_input("Number of rounds: ")
    rounds = int(rounds)
    return rounds

def receiveSalt():
    print "Please provide the salt."
    saltvalue = raw_input("Salt: ")
    return saltvalue

def receiveHash():
    print "Please provide the hash to use."
    receivedhash = raw_input("Hash: ")
    return receivedhash

def receiveUsername():
    print "Please provide the username you wish to use."
    receivedusername = raw_input("Username: ")
    return receivedusername
 
def generateRoundedHashes(hashchoice, stringprovided):
    print "Do you want to provide the salt used for hashing?"
    saltanswer = raw_input("[Y]es/[N]o: ")
    if saltanswer.lower() == "y" or saltanswer.lower() == "yes":
        saltvalue = receiveSalt()
        print "Do you want to provide the number of hashing rounds to use?"
        hashroundanswer = raw_input("[Y]es/[N]o: ")
        if hashroundanswer.lower() == "y" or hashroundanswer.lower() == "yes":
            rounders = roundGather()
            generatedhash = getattr(hashes, hashchoice).encrypt(stringprovided, rounds=rounders, salt=saltvalue)
            return generatedhash
        else:
            generatedhash = getattr(hashes, hashchoice).encrypt(stringprovided, salt=saltvalue)
            return generatedhash
    else:
        print "Do you want to provide the number of hashing rounds to use?"
        hashroundanswer = raw_input("[Y]es/[N]o: ")
        if hashroundanswer.lower() == "y" or hashroundanswer.lower() == "yes":
            rounders = roundGather()
            generatedhash = getattr(hashes, hashchoice).encrypt(stringprovided, rounds=rounders)
            return generatedhash
        else:
            generatedhash = getattr(hashes, hashchoice).encrypt(stringprovided)
            return generatedhash

def generateMD5CryptedHash(hashchoice, stringprovided):
    print "Do you want to provide the salt used for hashing?"
    saltanswer = raw_input("[Y]es/[N]o: ")
    if saltanswer.lower() == "y" or saltanswer.lower() == "yes":
        saltvalue = receiveSalt()
        generatedhash = getattr(hashes, hashchoice).encrypt(stringprovided, salt=saltvalue)
        return generatedhash
    else:
        generatedhash = getattr(hashes, hashchoice).encrypt(stringprovided)
        return generatedhash

def generateHash(hashchoice, stringprovided):
    stringhashed = getattr(hashlib, hashchoice)()
    stringhashed.update(stringprovided)
    result = stringhashed.hexdigest()
    return result

def generateNTLM(stringprovided):
    lmhashed = hashes.lmhash.encrypt(stringprovided)
    nthashed = hashes.nthash.encrypt(stringprovided)
    return (lmhashed, nthashed)

def generateMSDCC(hashchoice, stringprovided):
    msusername = receiveUsername()
    generatedhash = getattr(hashes, hashchoice).encrypt(stringprovided, user=msusername)    
    return generatedhash

def compareHash(hashchoice, stringprovided, mainhash):
    verified = getattr(hashes, hashchoice).verify(stringprovided, mainhash)
    if verified == True:
        print "TRUE - The hash \"" + mainhash + "\" and \"" + stringprovided + "\" match!"
    else:
        print "FALSE - The hash \"" + mainhash + "\" and plaintext \"" + stringprovided + "\" do not match!"

def compareNTLM(hashchoice, stringprovided, mainhash):
    verifiedlm = hashes.lmhash.verify(stringprovided, mainhash.split(":")[0])
    verifiednt = hashes.nthash.verify(stringprovided, mainhash.split(":")[1])
    if verifiedlm == True and verifiednt == True:
        print "TRUE - The hash \"" + mainhash + "\" and \"" + stringprovided + "\" match!"
    else:
        print "FALSE - The hash \"" + mainhash + "\" and plaintext \"" + stringprovided + "\" do not match!"

def compareStraightHash(hashchoice, stringprovided, mainhash):
    hashedstring = getattr(hashlib, hashchoice)()
    hashedstring.update(stringprovided)
    resultinghash = hashedstring.hexdigest()
    if mainhash == resultinghash:
        print "TRUE - The hash \"" + mainhash + "\" and \"" + stringprovided + "\" match!"
    else:
        print "FALSE - The hash \"" + mainhash + "\" and plaintext \"" + stringprovided + "\" do not match!"

def compareMSDCC(hashchoice, stringprovided, mainhash):
    msusername = receiveUsername()
    verifiedhash = getattr(hashes, hashchoice).verify(stringprovided, mainhash, user=msusername)
    if verifiedhash == True:
        print "TRUE - The hash \"" + mainhash + "\" and \"" + stringprovided + "\" match!"
    else:
        print "FALSE - The hash \"" + mainhash + "\" and plaintext \"" + stringprovided + "\" do not match!"

printTitle()
menuchoice = printorCheck()
printTitle()
hashchoice = supportedHashes()
printTitle()
stringprovided = getPlaintext(menuchoice)
if hashchoice == "md5" or hashchoice == "sha1" or hashchoice == "sha256" or hashchoice == "sha512":
    printTitle()
    if menuchoice == "generate":
        fullhash = generateHash(hashchoice, stringprovided)
        print "The hashed value of \"" + stringprovided + "\" is:\n"
        print fullhash
    else:
        mainhash = receiveHash()
        compareStraightHash(hashchoice, stringprovided, mainhash)
elif hashchoice == "md5_crypt":
    printTitle()
    if menuchoice == "generate":
        fullhash = generateMD5CryptedHash(hashchoice, stringprovided)
        print "The hashed value of \"" + stringprovided + "\" is:\n"
        print fullhash
    else:
        mainhash = receiveHash()
        compareHash(hashchoice, stringprovided, mainhash)
elif hashchoice == "sha1_crypt" or hashchoice == "sha256_crypt":
    printTitle()
    if menuchoice == "generate":
        fullhash = generateRoundedHashes(hashchoice, stringprovided)
        print "The hashed value of \"" + stringprovided + "\" is:\n"
        print fullhash
    else:
        mainhash = receiveHash()
        compareHash(hashchoice, stringprovided, mainhash)
elif hashchoice == "NTLM":
    printTitle()
    if menuchoice == "generate":
        lmhash, nthash = generateNTLM(stringprovided)
        print "The NTLM hash of \"" + stringprovided + "\" is:\n"
        print "LM Hash: " + lmhash
        print "NT Hash: " + nthash
        print "NTLM : " + lmhash + ":" + nthash
    else:
        mainhash = receiveHash()
        compareNTLM(hashchoice, stringprovided, mainhash)
elif hashchoice == "msdcc" or hashchoice == "msdcc2":
    if menuchoice == "generate":
        printTitle()
        fullhash = generateMSDCC(hashchoice, stringprovided)
        print "The hashed value of \"" + stringprovided + "\" is:\n"
        print fullhash
    else:
        mainhash = receiveHash()
        compareMSDCC(hashchoice, stringprovided, mainhash)