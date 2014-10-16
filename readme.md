browserify-aes [![Build Status](https://travis-ci.org/calvinmetcalf/browserify-aes.svg)](https://travis-ci.org/calvinmetcalf/browserify-aes)
====

much of this taken from the aes implimentation in [triplesec](https://github.com/keybase/triplesec), they are just normal streams for now, no fancy stuff.

EVP_BytesToKey is a strait up port of the same function from openssl as there is literally no documenation on it beyond it using 'undocumented extentions' for longer keys.