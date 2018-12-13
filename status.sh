#!/bin/sh

curl -m 5 --retry 2 localhost
if [ $? = 0 ]
then
    echo "攻撃されていない"
else
    echo "攻撃されている"
fi


