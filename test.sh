#!/bin/sh

for i in "*.go" "authentication/*.go" "authorization/*.go"; do
    echo Processing $i ...
    go test -cover $i
    if [ $? -ne 0 ]; then
        exit 1
    fi
done

# cleanup
rm -f auth*/*.test *.test
