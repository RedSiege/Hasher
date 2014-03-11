Hasher
======

Hasher is designed to be a tool that allows you to quickly hash plaintext strings, or compare hashed values with a plaintext locally.  The reason I wrote this is because when on an assessment, I don't, and won't, send hashes that I found to an online "hash generator" that I don't trust.  I'd rather have an easy way to generate hash values, or compare hashes to plaintext values, quickly.  Hasher does this.

Install:

Run the setup.sh script (./setup.sh)
The setup script installs two python libraries that hasher invokes (passlib and py-bcrypt).

Alternatively, you can use Pip/Virtualenv.
```
# Create a virtualenv (e.g. venv)
virtualenv venv
# Install the requirements
pip install -r requirements.txt
```

Use:
It's menu driven, if you have questions, just ask me

There are also command line options that can be shown with the -h or --help flag
```
./Hasher.py --help
```
