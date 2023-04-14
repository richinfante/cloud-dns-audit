#!/bin/bash

mkdir -p ip-ranges
# aws
curl https://ip-ranges.amazonaws.com/ip-ranges.json > ip-ranges/aws.json

# azure
curl 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519' > ip-ranges/azure.json