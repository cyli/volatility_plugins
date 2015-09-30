#!/usr/bin/env bash

# Verify that the volatility plugins work with VMWare (Fusion on OSX)
# This general should technically also work with VMWare for windows or linux,
# but the paths are different and must be specified.

# See https://www.vmware.com/support/developer/vix-api/vix111_vmrun_command.pdf


# --- Download and set up volatility ---
if [[ ! -d "volatility" ]]; then
    git clone -b 2.4.1 --single-branch https://github.com/volatilityfoundation/volatility.git
fi

if [[ ! -d ".vol_venv" ]]; then
    virtualenv .vol_venv
    source .vol_venv/bin/activate
    pip install volatility/
fi


# --- Set up vmware ---
if [[ "$(uname)" == 'Darwin' ]]; then
   export PATH="${PATH}:/Applications/VMware Fusion.app/Contents/Library"
   PROVIDER=vmware_fusion
fi


# --- Build the profile if it's not there ---
if [[ ! -f "volatility/volatility/plugins/overlays/linux/Ubuntu1404.zip" ]]; then
    vagrant up profile --provider="${PROVIDER}"
    vagrant suspend profile
fi

# --- Set up the memory testing box ---
# if [[ "$(uname)" == 'Darwin' ]]; then
#    export PATH="${PATH}:/Applications/VMware Fusion.app/Contents/Library"
#    PROVIDER=vmware_fusion
# fi
# vagrant up --provider="${PROVIDER}"


# # --- Acquire memory ---
# VMX="$(cat .vagrant/machines/default/${PROVIDER}/id)"
# if [[ -z "$(vmrun listSnapshots "${VMX}" | grep keys_and_python)" ]]; then
#     vmrun snapshot "${VMX}" keys_and_python
# fi

# SNAPSHOT="$(echo ${VMX} | sed "s/\.vmx$"/-Snapshot1.vmem/g)"

# # --- Setup volatility ---
