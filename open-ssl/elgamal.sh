#!/bin/bash

./rsa.sh
openssl dgst -sha1 -sign private.pem -out sign.bin file.txt
openssl dgst -sha1 -verify public.pem -signature sign.bin file.txt
