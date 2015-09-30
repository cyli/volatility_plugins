#!/usr/bin/env bash

DIR=/opt/testingdir

# find the most recent SSH-agent
export SSH_AUTH_SOCK=$(find /tmp/ssh-* -user `whoami` -name agent\* -printf '%T@ %p\n' 2>/dev/null | sort -k 1nr | sed 's/^[^ ]* //' | head -n 1)
[[ -z "${SSH_AUTH_SOCK}" ]] && eval "$(ssh-agent -s)"


# minimum number of bits for ssh-keygen is 768
for bits in 768 2048 4096
do
    fname="${DIR}/id_rsa.${bits}"
    [[ ! -f "${fname}" ]] && ssh-keygen -b "${bits}" -f "${fname}" -N ""
    ssh-add "${fname}"
done


passwd_fname="${DIR}/id_rsa.4096.passwd"
password="passworded"
if [[ ! -f "${passwd_fname}" ]]; then
    ssh-keygen -b 4096 -f temp -N "${password}"
    openssl pkcs8 -topk8 -v2 des3 -in temp -out ${DIR}/id_rsa.4096.passwd -passout 'pass:${password}'
    rm temp temp.pub
fi
echo "${password}" | ssh-add "${passwd_fname}"


echo "SSH keys in ssh-agent"
ssh-add -L
