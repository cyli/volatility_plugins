#!/usr/bin/env bash

DIR=/opt/testingdir

# find the most recent SSH-agent
export SSH_AUTH_SOCK=$(find /tmp/ssh-* -user `whoami` -name agent\* -printf '%T@ %p\n' 2>/dev/null | sort -k 1nr | sed 's/^[^ ]* //' | head -n 1)
[[ -z "${SSH_AUTH_SOCK}" ]] && eval "$(ssh-agent -s)"


# minimum number of bits for ssh-keygen is 768
# For 4096, add the passworded version instead of the plaintext version
for bits in 768 2048 4096
do
    fname="${DIR}/id_rsa.${bits}"
    [[ ! -f "${fname}" ]] && ssh-keygen -b "${bits}" -f "${fname}" -N ""
    if [[ "${bits}" == 4096 ]]; then
        passwd_fname="${fname}.passwd"
        if [[ ! -f "${passwd_fname}" ]]; then
            openssl pkcs8 -topk8 -v2 des3 -in ${DIR}/id_rsa.4096 -out ${passwd_fname} -passout 'pass:${passworded}'
        fi
        echo "${passworded}" | ssh-add "${passwd_fname}"
    else
        ssh-add "${fname}"
    fi
done

rm "${DIR}/*.pub"
