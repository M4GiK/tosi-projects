#!/bin/bash

echo -n "The quick brown fox jumps over the lazy dog" | openssl sha1 > digest.txt
cat digest.txt
echo "hash above should be: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
