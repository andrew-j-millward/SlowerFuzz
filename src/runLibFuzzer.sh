#!/bin/sh

echo $1
echo $2
cd ../$1_tmp/
./$1-fsanitize_fuzzer -seed=$2