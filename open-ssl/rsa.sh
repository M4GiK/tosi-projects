#!/bin/bash

openssl genrsa -out private.pem 1024
openssl rsa -in private.pem -out public.pem -outform PEM -pubout
echo 'The quick brown fox jumps over the lazy dog' > file.txt
openssl rsautl -encrypt -inkey public.pem -pubin -in file.txt -out file.ssl
openssl rsautl -decrypt -inkey private.pem -in file.ssl -out decrypted.txt
cat decrypted.txt

