#! /bin/sh

BASEDIR=$(dirname $0)
sed -i "6r $BASEDIR/links.html" docs/index.html
sed -i "668r $BASEDIR/script.js" docs/main.js
