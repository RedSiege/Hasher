#!/usr/bin/env python
 
# Hashing Script which generates hashes from plaintext strings, and allows you to
# compare a string with a hash to determine if you have the correct cleartext string

# Author: Christopher Truncer
# Thanks for the help with stupid errors I couldn't solve from those who don't want to be named!
 
import os
import passlib.hash as hashes
import hashlib
import argparse
import sys

def cliParser():
    parser = argparse.ArgumentParser(description="Create or Verify hashes with plaintext strings.")
    parser.add_argument("-list", action="store_true", help="List all supported hash algorithms")
    parser.add_argument("-G", metavar="Plaintext String", help="Generate a hash from the provided string.")
    parser.add_argument("-C", metavar="Plaintext String", help="Compare provided plaintext with a hash")
    parser.add_argument("-type", metavar="HASH_TYPE", help="The hashing algorithm you want to use")
    parser.add_argument("-hash", metavar="HASH", help="Hash used for comparison")
    parser.add_argument("-rounds", metavar="5000", help="Number of rounds to hash your plaintext string")
    parser.add_argument("-salt", metavar="SALT", help="Salt used for hashing")
    parser.add_argument("-username", metavar="USERNAME", help="Only required for select hash types")
    args = parser.parse_args()

    if args.G:
        # Set our input flags to variables
        string = args.G
        hashalgo = args.type
        salt = args.salt
        rounds = args.rounds
        msusername = args.username

        #Detect hash type for hash generation
        if hashalgo == "md5" or hashalgo == "sha1" or hashalgo == "sha256" or hashalgo == "sha512":
            userhash = getattr(hashlib, hashalgo)()
            userhash.update(string)
            result = userhash.hexdigest()
            print result
        elif hashalgo == "ntlm":
            lmhash, nthash = generateNTLM(string)
            print "The NTLM hash of \"" + string + "\" is:\n"
            print "LM Hash: " + lmhash
            print "NT Hash: " + nthash
            print "NTLM : " + lmhash + ":" + nthash
        elif hashalgo == "msdcc" or hashalgo == "msdcc2" or hashalgo == "postgres_md5" or hashalgo == "oracle10g" or hashalgo == "cisco_pix":
            try:
                userhash = generateUsernameHash(hashalgo, string, msusername)
                print userhash
            except TypeError:
                print "Error: A username is required for msdcc, msdcc2, postgres_md5, oracle10g, and cisco_pix hashes"
        elif hashalgo == "md5_crypt" or hashalgo == "ldap_salted_md5" or hashalgo == "ldap_salted_sha1":
            if salt:
                try:
                    generatedhash = getattr(hashes, hashalgo).encrypt(string, salt=salt)
                    print generatedhash
                except ValueError:
                    print "Error: Salt size not correct. ldap_salted_md5/sha1 need salt of 4-16 characters"
            else:
                generatedhash = getattr(hashes, hashalgo).encrypt(string)
                print generatedhash
        elif hashalgo == "sha1_crypt" or hashalgo == "sha256_crypt" or hashalgo == "sha512_crypt" or hashalgo == "bcrypt":
            if salt:
                if rounds:
                    try:
                        generatedhash = getattr(hashes, hashalgo).encrypt(string, rounds=int(rounds), salt=salt)
                        print generatedhash
                    except ValueError:
                        print "Sha256_crypt and sha512_crypt require at least 1000 rounds."
                        print "Bcrypt rounds must be between 4 and 31."
                else:
                    generatedhash = getattr(hashes, hashalgo).encrypt(string, salt=salt)
                    print generatedhash
            else:
                if rounds:
                    try:
                        generatedhash = getattr(hashes, hashalgo).encrypt(string, rounds=int(rounds))
                        print generatedhash
                    except ValueError:
                        print "Error: sha256_crypt and sha512_crypt require at least 1000 rounds."
                else:
                    generatedhash = getattr(hashes, hashalgo).encrypt(string)
                    print generatedhash
        elif hashalgo == "mssql2000" or hashalgo == "mssql2005" or hashalgo == "mysql323" or hashalgo == "mysql41" or hashalgo == "oracle11" or hashalgo == "cisco_type7" or hashalgo == "ldap_md5" or hashalgo == "ldap_sha1":
            try:
                generatedhash = generateEasyPasslibHash(hashalgo, string)
                print generatedhash
            except:
                "Error - Please open a github issue letting me know about this error"
        sys.exit()

    elif args.C:
        string = args.C
        hashalgo = args.type
        cipherhash = str(args.hash)
        msusername = args.username

        if hashalgo == "md5" or hashalgo == "sha1" or hashalgo == "sha256" or hashalgo == "sha512":
            compareStraightHash(hashalgo, string, cipherhash)
        elif hashalgo == "mssql2000" or hashalgo == "mssql2005" or hashalgo == "mysql323" or hashalgo == "mysql41" or hashalgo == "oracle11" or hashalgo == "cisco_type7" or hashalgo == "ldap_md5" or hashalgo == "ldap_sha1":
            try:
                compareEasyPasslibHash(hashalgo, string, cipherhash)
            except:
                print "Error - Please open a github issue letting me know about this error"
        elif hashalgo == "ntlm":
            try:
                compareNTLM(hashalgo, string, cipherhash)
            except ValueError:
                print "Error: You didn't provide a valid ntlm hash."
        elif hashalgo == "sha1_crypt" or hashalgo == "sha256_crypt" or hashalgo == "sha512_crypt" or hashalgo == "bcrypt":
            try:
                compareHash(hashalgo, string, cipherhash)
            except ValueError:
                print "Error: You didn't provide a valid hash."
        elif hashalgo == "msdcc" or hashalgo == "msdcc2" or hashalgo == "postgres_md5" or "oracle10g" or hashalgo == "cisco_pix":
            try:
                compareUsernameHash(hashalgo, string, cipherhash, msusername)
            except TypeError:
                print "Error: You need to provide a username for this hash type."
            except ValueError:
                print "Error: You didn't provide a valid hash."
        elif hashalgo == "md5_crypt" or hashalgo == "ldap_salted_md5" or hashalgo == "ldap_salted_sha1":
            try:
                compareHash(hashalgo, string, cipherhash)
            except ValueError:
                print "Error: Salt size not correct.  Ldap_salted_md5/sha1 need salt of 4-16 characters"
            except:
                print "Error: You didn't provide a valid md5_crypt hash."
        sys.exit()
    elif args.list:
        print "Supported hashing algorithms are:\n"
        print "md5, sha1, sha256, sha512, ntlm, msdcc, msdcc2, md5_crypt, sha1_crypt, sha256_crypt, sha512_crypt, mssql2000, mssql2005, mysql323, mysql41, oracle10, oracle11, postgres_md5, bcrypt, cisco_pix, cisco_type7, ldap_md5, ldap_salted_md5, ldap_sha1, ldap_salted_sha1"
        sys.exit()
    

def printTitle():
    os.system("clear")
    print "##############################################################################"
    print "#                                Hasher v1.0.4                               #"
    print "##############################################################################\n"
 
def printorCheck():
    print "Hasher generates hashes, or compares a plaintext string with a hash."
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
    print "1 - MD5\t\t\t\t16 - Oracle 10G"
    print "2 - SHA1\t\t\t17 - Oracle11G"
    print "3 - SHA256\t\t\t18 - Postgresql MD5"
    print "4 - SHA512\t\t\t19 - Bcrypt"
    print "5 - NTLM\t\t\t20 - Cisco PIX (Type 5)"
    print "6 - MS Domain Cached\t\t21 - Cisco Type 7"
    print "7 - MS Domain Cached v2\t\t22 - LDAP MD5"
    print "8 - MD5 Crypt\t\t\t23 - LDAP Salted MD5"
    print "9 - SHA1 Crypt\t\t\t24 - LDAP SHA1"
    print "10 - SHA256 Crypt\t\t25 - LDAP Salted SHA1"
    print "11 - SHA512 Crypt"
    print "12 - MSSQL 2000"
    print "13 - MSSQL 2005"
    print "14 - MYSQL v3.2.3\t\t99 - Exit Hasher"
    print "15 - MYSQL v4.1\n"
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
    elif hashselection == "11":
        hashselection = "sha512_crypt"
        return hashselection
    elif hashselection == "12":
        hashselection = "mssql2000"
        return hashselection
    elif hashselection == "13":
        hashselection = "mssql2005"
        return hashselection
    elif hashselection == "14":
        hashselection = "mysql323"
        return hashselection
    elif hashselection == "15":
        hashselection = "mysql41"
        return hashselection
    elif hashselection == "16":
        hashselection = "oracle10"
        return hashselection
    elif hashselection == "17":
        hashselection = "oracle11"
        return hashselection
    elif hashselection == "18":
        hashselection = "postgres_md5"
        return hashselection
    elif hashselection == "19":
        hashselection = "bcrypt"
        return hashselection
    elif hashselection == "20":
        hashselection = "cisco_pix"
        return hashselection
    elif hashselection == "21":
        hashselection = "cisco_type7"
        return hashselection
    elif hashselection == "22":
        hashselection = "ldap_md5"
        return hashselection
    elif hashselection == "23":
        hashselection = "ldap_salted_md5"
        return hashselection
    elif hashselection == "24":
        hashselection = "ldap_sha1"
        return hashselection
    elif hashselection == "25":
        hashselection = "ldap_salted_sha1"
        return hashselection
    elif hashselection == "99":
        sys.exit("\nThanks for using Hasher!")
    else:
        "This will now error because you didn't provide a valid selection, and I didn't implement error checking yet"
    return hashselection
 
def getPlaintext(menuchoice):
    if menuchoice == "generate":
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
 
def generateRoundedHashes(hashchoice, stringprovided):
    print "Do you want to provide the salt used for hashing?"
    saltanswer = raw_input("[Y]es/[N]o: ")
    if saltanswer.lower() == "y" or saltanswer.lower() == "yes":
        saltvalue = receiveSalt()
        print "Do you want to provide the number of hashing rounds to use?"
        hashroundanswer = raw_input("[Y]es/[N]o: ")
        if hashroundanswer.lower() == "y" or hashroundanswer.lower() == "yes":
            rounders = roundGather()
            try:
                generatedhash = getattr(hashes, hashchoice).encrypt(stringprovided, rounds=rounders, salt=saltvalue)
            except ValueError:
                print "Error: BCrypt requres a salt of 22 alphanumeric characters"
            return generatedhash
        else:
            try:
                generatedhash = getattr(hashes, hashchoice).encrypt(stringprovided, salt=saltvalue)
            except ValueError:
                print "Error: BCrypt requres a salt of 22 alphanumeric characters"
                sys.exit()
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

def generateCryptedorSaltedHash(hashchoice, stringprovided):
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

def generateUsernameHash(hashchoice, stringprovided, msusername):
    generatedhash = getattr(hashes, hashchoice).encrypt(stringprovided, user=msusername)    
    return generatedhash

def compareHash(hashchoice, stringprovided, mainhash):
    verified = getattr(hashes, hashchoice).verify(stringprovided, mainhash)
    if verified == True:
        print "TRUE - The hash \"" + mainhash + "\" and \"" + stringprovided + "\" match!"
    else:
        print "FALSE - The hash \"" + mainhash + "\" and plaintext \"" + stringprovided + "\" do not match!"

# Microsoft NTLM Hashes
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

# Microsoft Domain Cached Credential Hash function
def compareUsernameHash(hashchoice, stringprovided, mainhash, username):
    verifiedhash = getattr(hashes, hashchoice).verify(stringprovided, mainhash, user=username)
    if verifiedhash == True:
        print "TRUE - The hash \"" + mainhash + "\" and \"" + stringprovided + "\" match!"
    else:
        print "FALSE - The hash \"" + mainhash + "\" and plaintext \"" + stringprovided + "\" do not match!"

# Function for generating MSSQL, MYSQL, and Oracle 11G Database hashes
def generateEasyPasslibHash(hashchoice, stringprovided):
    hashedstring = getattr(hashes, hashchoice).encrypt(stringprovided)
    return hashedstring

# Function for comparing MSSQL, MYSQL, and Oracle 11G Database hashes
def compareEasyPasslibHash(hashchoice, stringprovided, mainhash):
    verifiedhash = getattr(hashes, hashchoice).verify(stringprovided, mainhash)
    if verifiedhash == True:
        print "TRUE - The hash \"" + mainhash + "\" and \"" + stringprovided + "\" match!"
    else:
        print "FALSE - The hash \"" + mainhash + "\" and plaintext \"" + stringprovided + "\" do not match!"

def main():
    printTitle()
    menuchoice = str(printorCheck())
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
    elif hashchoice == "md5_crypt" or hashchoice == "ldap_salted_md5" or hashchoice == "ldap_salted_sha1":
        printTitle()
        if menuchoice == "generate":
            fullhash = generateCryptedorSaltedHash(hashchoice, stringprovided)
            print "The hashed value of \"" + stringprovided + "\" is:\n"
            print fullhash
        else:
            mainhash = receiveHash()
            try:
                compareHash(hashchoice, stringprovided, mainhash)
            except ValueError:
                print "Error: You didn't provide a valid hash."
    elif hashchoice == "sha1_crypt" or hashchoice == "sha256_crypt" or hashchoice == "sha512_crypt" or hashchoice == "bcrypt" or hashchoice == "cisco_type7":
        printTitle()
        if menuchoice == "generate":
            fullhash = generateRoundedHashes(hashchoice, stringprovided)
            print "The hashed value of \"" + stringprovided + "\" is:\n"
            print fullhash
        else:
            mainhash = receiveHash()
            try:
                compareHash(hashchoice, stringprovided, mainhash)
            except:
                print "Error: You didn't provide a valid hash."
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
            try:
                compareNTLM(hashchoice, stringprovided, mainhash)
            except ValueError:
                print "Error: You provided an invalid NTLM hash."
    elif hashchoice == "msdcc" or hashchoice == "msdcc2" or hashchoice == "postgres_md5" or hashchoice == "oracle10" or hashchoice == "cisco_pix":
        if menuchoice == "generate":
            printTitle()
            usernameinput = raw_input("What is the username?: ")
            fullhash = generateUsernameHash(hashchoice, stringprovided, usernameinput)
            print "The hashed value of \"" + stringprovided + "\" and the username \"" + usernameinput + "\" is:\n"
            print fullhash
        else:
            mainhash = receiveHash()
            username = raw_input("What is the username associated with the hash: ")
            if username == '':
                print "\nWARNING: You didn't enter a username! This will impact the hash value!\n"
            try:
                compareUsernameHash(hashchoice, stringprovided, mainhash, username)
            except ValueError:
                print "Error: You didn't provide a valid hash."
    elif hashchoice == "mssql2000" or hashchoice == "mssql2005" or hashchoice == "mysql323" or hashchoice == "mysql41" or hashchoice == "oracle11" or hashchoice == "cisco_type7" or hashchoice == "ldap_md5" or hashchoice == "ldap_sha1":
        if menuchoice == "generate":
            printTitle()
            fullhash = generateEasyPasslibHash(hashchoice, stringprovided)
            print "The hashed value of \"" + stringprovided + "\" is:\n"
            print fullhash
        else:
            printTitle()
            mainhash = receiveHash()
            try:
                compareEasyPasslibHash(hashchoice, stringprovided, mainhash)
            except:
                print "Error - Please open github issue letting me know about this error"

try:
    cliParser()
    main()
except KeyboardInterrupt:
    print "\n\nRage quit!!!  :)"
