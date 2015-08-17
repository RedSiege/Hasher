'''
This file is the conductor of everything Hasher.
'''

import argparse
import glob
import imp
import sys
from hashes.common import helpers
import hashes.ops.bcrypt
import hashes.ops.cisco_pix
import hashes.ops.cisco_type7
import hashes.ops.ldap_md5
import hashes.ops.ldap_salted_md5
import hashes.ops.ldap_salted_sha1
import hashes.ops.ldap_sha1
import hashes.ops.md5_crypt
import hashes.ops.md5
import hashes.ops.msdcc2
import hashes.ops.msdcc
import hashes.ops.mssql2000
import hashes.ops.mssql2005
import hashes.ops.mysql323
import hashes.ops.mysql41
import hashes.ops.nt
import hashes.ops.oracle10
import hashes.ops.oracle11
import hashes.ops.postgres_md5
import hashes.ops.sha1_crypt
import hashes.ops.sha1
import hashes.ops.sha256_crypt
import hashes.ops.sha256
import hashes.ops.sha512_crypt
import hashes.ops.sha512


_OPS_ALGORITHMS = [
    hashes.ops.bcrypt.Algorithm,
    hashes.ops.cisco_pix.Algorithm,
    hashes.ops.cisco_type7.Algorithm,
    hashes.ops.ldap_md5.Algorithm,
    hashes.ops.ldap_salted_md5.Algorithm,
    hashes.ops.ldap_salted_sha1.Algorithm,
    hashes.ops.ldap_sha1.Algorithm,
    hashes.ops.md5_crypt.Algorithm,
    hashes.ops.md5.Algorithm,
    hashes.ops.msdcc2.Algorithm,
    hashes.ops.msdcc.Algorithm,
    hashes.ops.mssql2000.Algorithm,
    hashes.ops.mssql2005.Algorithm,
    hashes.ops.mysql323.Algorithm,
    hashes.ops.mysql41.Algorithm,
    hashes.ops.nt.Algorithm,
    hashes.ops.oracle10.Algorithm,
    hashes.ops.oracle11.Algorithm,
    hashes.ops.postgres_md5.Algorithm,
    hashes.ops.sha1_crypt.Algorithm,
    hashes.ops.sha1.Algorithm,
    hashes.ops.sha256_crypt.Algorithm,
    hashes.ops.sha256.Algorithm,
    hashes.ops.sha512_crypt.Algorithm,
    hashes.ops.sha512.Algorithm,
    ]


class Conductor:
    def __init__(self):
            # default values of object attributes
            self.username = ''
            self.password = ''
            self.hash_value = ''
            self.hash_type = ''
            self.rounds = 5000
            self.salt = ''
            self.action = ''

            # Dictionary containing hashing algorithms
            self.hashing_algorithms = {}

    def cliParser(self):
        parser = argparse.ArgumentParser(description="Create or Verify hashes with plaintext strings.")
        parser.add_argument("--list", action="store_true", default=False, help="List all supported hash algorithms")
        parser.add_argument("-G", default=False, help="Generate a hash from the provided string.", action='store_true')
        parser.add_argument("-C", default=False, help="Compare provided plaintext with a hash", action='store_true')
        parser.add_argument("--hash-type", metavar="md5", default=None, help="The hashing algorithm you want to use")
        parser.add_argument("--plaintext", metavar="password", default=None, help="Plaintext string to hash")
        parser.add_argument("--hash", metavar="HASH", default=None, help="Hash used for comparison")
        parser.add_argument("--rounds", metavar="5000", default=False, type=int, help="Number of rounds to hash your plaintext string")
        parser.add_argument("--salt", metavar="SALT", default=False, help="Salt used for hashing")
        parser.add_argument("--username", metavar="USERNAME", default=None, help="Only required for select hash types")
        args = parser.parse_args()
        if not args.G and not args.C and not args.list:
            print helpers.color("\n\n[*] Error: You must provide an action to perform", warning=True)
            print helpers.color("[*] Actions: [G]enerate or [C]ompare hashes.", warning=True)
            print helpers.color("[*] Please provide an action and re-run Hasher.", warning=True)
            sys.exit()

        if args.G and (args.plaintext is None or args.hash_type is None) :
            print helpers.color("\n\n[*] Error: You must provde a plaintext string and hashing algorithm to use!", warning=True)
            print helpers.color("[*] Please re-run and provide a plaintext string and/or hash algorithm.", warning=True)
            sys.exit()

        if args.C and (args.plaintext is None or args.hash_type is None or args.hash is None):
            print helpers.color("\n\n[*] Error: Comparison function requires plaintext string, hash digest, and hash algorithm.", warning=True)
            print helpers.color("[*] Please re-run and provide the required options", warning=True)
            sys.exit()
        return args

    def load_hash_operations(self):
        for algorithm_callable in _OPS_ALGORITHMS:
            algorithm = algorithm_callable()
            self.hashing_algorithms[algorithm.hash_type] = algorithm

    def menu_system(self):

        # Parse the command line arguments and load up hashing modules
        cli_args = self.cliParser()
        self.load_hash_operations()

        # If listing payloads, do it and then exit
        if cli_args.list:
            print "Supported Hashing Algorithms: "
            for path, hash_obj in self.hashing_algorithms.iteritems():
                print "[*] " + hash_obj.hash_type
            sys.exit()

        # Generate a hash digest for the provided plaintext string
        # Iterates over all loaded hash_op modules, finds the hash type
        # generates the digest, and returns it
        if cli_args.G:
            if cli_args.hash_type.lower().strip() == "all":
                print "Plaintext string : " + helpers.color(cli_args.plaintext)
            for path, hash_obj in self.hashing_algorithms.iteritems():

                if cli_args.hash_type.lower().strip() == "all":
                    hashed_string = hash_obj.generate(cli_args)
                    print hash_obj.hash_type + " hash : " + helpers.color(hashed_string)

                elif cli_args.hash_type.lower().strip() == hash_obj.hash_type.lower():
                    hashed_string = hash_obj.generate(cli_args)
                    print "Hash Type        : " + helpers.color(cli_args.hash_type)
                    print "Plaintext string : " + helpers.color(cli_args.plaintext)
                    print "Digest Value     : " + helpers.color(hashed_string)

        if cli_args.C:
            found_hash = False
            for path, hash_obj in self.hashing_algorithms.iteritems():
                if cli_args.hash_type.lower().strip() == hash_obj.hash_type.lower():
                    hashed_string = hash_obj.generate(cli_args)
                    found_hash = True
                    if hashed_string == cli_args.hash.lower().strip():
                        print helpers.color("True - The hash " + cli_args.hash + " and plaintext " + cli_args.plaintext + " match!")
                    else:
                        print helpers.color("False - The hash " + cli_args.hash + " and plaintext " + cli_args.plaintext + " do not match!", warning=True)
            if not found_hash:
                print helpers.color("[*] Error: You did not provide a valid hash-type to compare!", warning=True)
                print helpers.color("[*] Error: Please re-run with a valid hash-type.", warning=True)

        return
