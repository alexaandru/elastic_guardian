#!/bin/sh

for i in "authentication/*.go" "authorization/*.go"; do
    go test $i
    if [ $? -ne 0 ]; then
        exit 1
    fi
done
