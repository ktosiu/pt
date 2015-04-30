#! /bin/bash

if [[ -f "./src/VERSION" ]]; then
    rm -rf /src/VERSION
fi

touch "./src/VERSION"
if [[ $? -ne 0 ]]; then
    echo touch version file failed
    exit 1
fi

git show-ref --heads > ./src/VERSION

tar -cvjf pt.git`git show -s --pretty='tformat:%h' HEAD`.tar.gz ./src

