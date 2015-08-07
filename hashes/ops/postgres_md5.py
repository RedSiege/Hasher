'''
This module generates md5 hashes
'''

import sys
from passlib.hash import postgres_md5


class Algorithm:

    def __init__(self):
        self.hash_type = "postgres_md5"
        self.description = "This module generates postgres_md5 hashes"

    def generate(self, cli_object):
        if cli_object.username is None:
            print "You must provide a username for postgres_md5 hashes!"
            return "Postgres_md5 Hashes require a username"
        generatedhash = postgres_md5.encrypt(cli_object.plaintext, user=cli_object.username)    
        return generatedhash
