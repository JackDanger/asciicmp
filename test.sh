#!/bin/bash

interface=$1
if [[ -z "${interface}" ]]; then
  >&2 echo "USAGE: ${0} interface"
  exit 1
fi

set -euo pipefail

pping() {
  echo "in"
  set -x
  if uname | grep -q 'Darwin'; then
    ping -S $(ipconfig getifaddr ${interface}) $@ &>/dev/null &
  else
    ping -I ${interface} $@ &>/dev/null &
  fi
}

go build main.go 
set -x
pping yahoo.com -c 2

sudo ./main -i ${interface}
