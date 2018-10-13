#!/bin/sh

# Sample Cirrus Scan check
# see wrapper.py for environment setup

if [ ! -z "${VERBOSE}" ]; then
    echo "Verbose is set to ${VERBOSE}"
else
    echo "Verbose is not set"
fi

date
echo "Performing check..."

sha256sum /root/input1.txt > /root/output1.txt
sha256sum /root/input2.txt > /root/output2.txt

