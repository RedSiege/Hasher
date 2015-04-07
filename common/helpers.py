'''
This part of Hasher contains misc. functions for use throughout
the tool.
'''

import os


# Taken from veil-evasion
def color(string, status=True, warning=False, bold=True):
    """
    Change text color for the linux terminal, defaults to green.
    Set "warning=True" for red.
    """
    attr = []
    if status:
        # green
        attr.append('32')
    if warning:
        # red
        attr.append('31')
    if bold:
        attr.append('1')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)


def print_header():
    os.system("clear")
    print "#" * 80
    print "#" + " " * 36 + "Hasher" + " " * 36 + "#"
    print "#" * 80 + "\n"


def receiveSalt():
    print "Please provide the salt."
    saltvalue = raw_input("Salt: ").strip()
    return saltvalue


def roundGather():
    print "How many rounds of hashing would you like?"
    rounds = int(raw_input("Number of rounds: "))
    return rounds
