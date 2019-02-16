#!/bin/bash

set -euo pipefail

go build main.go 
(sleep 1 && ping yahoo.com -S 192.168.7.57 -c 1 &>/dev/null) &
sudo ./main -i en0
