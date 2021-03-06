#!/bin/bash
rm -rf out || exit 0;
mkdir out; 
( cd out
 git init
 git config user.name "Kauhsa"
 git config user.email "kauhsa@kapsi.fi"
 cp ../dist/kandi.pdf ./kandi.pdf
 git add .
 git commit -m "Deployed to Github Pages"
 git push --force --quiet "https://${GH_TOKEN}@${GH_REF}" master:gh-pages > /dev/null 2>&1
)