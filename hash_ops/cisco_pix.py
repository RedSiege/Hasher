'''
This module generates cisco_pix hashes
'''

from passlib.hash import cisco_pix


class Algorithm:

    def __init__(self):
        self.hash_type = "cisco_pix"
        self.description = "This module generates cisco_pix hashes"

    def generate(self, cli_object):
        if cli_object.username is None:
            print "You must provide a username for cisco_pix hashes!"
            return "Cisco_pix hashes require a username"
        generatedhash = cisco_pix.encrypt(cli_object.plaintext, user=cli_object.username)    
        return generatedhash
