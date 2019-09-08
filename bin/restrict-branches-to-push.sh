#!/usr/bin/env bash

current_branch=$(git symbolic-ref HEAD | sed -e 's,.*/\(.*\),\1,')

echo "[Branch Check] Verifying if current branch $current_branch is allowed to push directly."

if [ "$current_branch" = "master" ]
then
    echo "[Branch Check Error] Not allow to push to $current_branch branch"
    exit 1 # push will not execute
else
    echo "[Branch Check] Allow to push to $current_branch branch"
    exit 0 # push will execute
fi
