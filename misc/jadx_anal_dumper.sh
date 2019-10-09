#!/bin/bash

set -e

KEYWORD="ANAL"
SEARCH_LOC=$1

target_files=$(grep -Fr "** $KEYWORD" -l "$SEARCH_LOC")

for file in ${target_files}
do
    echo ">>>>>>>>>>>>>>>>> $file"
    echo
    sed -n "/\*\* $KEYWORD/,/\*\//p" "$file"
    echo
    echo "<<<<<<<<<<<<<<<<<<<<<<<"
    echo
done
