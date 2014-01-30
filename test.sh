#!/bin/sh

for i in "authentication/*.go" "authorization/*.go"; do
    go test -cover $i
    if [ $? -ne 0 ]; then
        exit 1
    fi
done

# cleanup
rm -f auth*/*.test
