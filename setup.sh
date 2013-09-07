#!/bin/bash

# Setup script for installing hasher's dependencies

# Ensure we have the python-dev package
apt-get install python-dev

# Download the dependencies
wget https://passlib.googlecode.com/files/passlib-1.6.1.tar.gz
wget https://py-bcrypt.googlecode.com/files/py-bcrypt-0.4.tar.gz

# Extract our files
tar -zxvf passlib-1.6.1.tar.gz
tar -zxvf py-bcrypt-0.4.tar.gz

# delete the archives
rm passlib-1.6.1.tar.gz
rm py-bcrypt-0.4.tar.gz

# move into the passlib directory and install
cd passlib-1.6.1
python setup.py install

# move out of passlib and instal py-bcrypt
cd ../py-bcrypt-0.4
python setup.py install

# Remove the directories
rm -rf passlib-1.6.1
rm -rf py-bcrypt-0.4

# Remove the setup directory
../rm-rf setup
