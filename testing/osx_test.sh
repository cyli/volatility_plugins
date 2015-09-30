#!/usr/bin/env bash

# Verify that the volatility plugins work with VMWare (Fusion on OSX)
# This general should technically also work with VMWare for windows or linux,
# but the paths are different and must be specified.

# See https://www.vmware.com/support/developer/vix-api/vix111_vmrun_command.pdf


# --- Download and set up volatility ---
if [[ ! -d "volatility" ]]; then
    git clone --single-branch https://github.com/volatilityfoundation/volatility.git volatility
else
    echo "Volatility master has already been downloaded"
fi

if [[ ! -d ".vol_venv" ]]; then
    virtualenv .vol_venv
    source .vol_venv/bin/activate
    pip install distorm3 pycrypto
    pip install -e volatility/
else
    echo "Volatility virtualenv already set up"
    source .vol_venv/bin/activate
fi


# --- Set up vmware ---
if [[ "$(uname)" == 'Darwin' ]]; then
   export PATH="${PATH}:/Applications/VMware Fusion.app/Contents/Library"
   PROVIDER=vmware_fusion
else
    echo "Currently only OS X with VMWare Fusion is supported."
    exit 1
fi


# --- Build the profile if it's not there ---
if [[ ! -f "volatility/volatility/plugins/overlays/linux/Ubuntu1404.zip" ]]; then
    if [[ -z "$(vagrant status profile | grep 'not created')" ]]; then
        vagrant up profile
        vagrant provision profile
    else
        vagrant up profile --provider="${PROVIDER}"
    fi
    vagrant suspend profile
else
    echo "Linux profile for Ubuntu 14.04 already exists."
fi


# --- Set up the memory testing box and acquire memory ---
vagrant up testing --provider="${PROVIDER}"
VMX="$(cat .vagrant/machines/testing/${PROVIDER}/id)"

if [[ -z "$(vmrun listSnapshots "${VMX}" | grep keys_and_python)" ]]; then
    vmrun snapshot "${VMX}" keys_and_python
else
    echo "Snapshot for memory testing already exists."
fi
SNAPSHOT="$(echo ${VMX} | sed "s/\.vmx$"/-Snapshot1.vmem/g)"


# --- Test SSH keys ---
# vol.py --plugins=profiles:"$(dirname `pwd`)/plugins" --profile=LinuxUbuntu1404x64 -f "${SNAPSHOT}" linux_ssh_keys --dump-dir .
[[ $(ls *.ssh-agent.* | wc -l) =~ 4 ]] && >&2 echo "Should have found 4 keys"
