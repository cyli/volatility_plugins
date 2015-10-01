#!/usr/bin/env bash

DIR=/vagrant

# find the most recent SSH-agent
export SSH_AUTH_SOCK=$(find /tmp/ssh-* -user `whoami` -name agent\* -printf '%T@ %p\n' 2>/dev/null | sort -k 1nr | sed 's/^[^ ]* //' | head -n 1)
[[ -z "${SSH_AUTH_SOCK}" ]] && eval "$(ssh-agent -s)"


# minimum number of bits for ssh-keygen is 768
for bits in 768 2048 4096
do
    fname="${DIR}/id_rsa.${bits}"
    [[ ! -f "${fname}" ]] && ssh-keygen -b "${bits}" -f "${fname}" -N ""
    ssh-add "${fname}"
    rm -f "${fname}.pub"
done
