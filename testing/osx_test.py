#!/usr/bin/env python

"""
Verify that the volatility plugins work with VMWare (Fusion on OSX)
This general should technically also work with VMWare for windows or linux,
but the paths are different and must be specified.

See https://www.vmware.com/support/developer/vix-api/vix111_vmrun_command.pdf
"""
from __future__ import print_function

import os
import shutil
import subprocess


def run(command_args, printit=True, env=None, shell=False):
    """
    Execute the given command args.
    """
    if printit:
        subprocess.call(command_args, env=env, shell=shell)
    else:
        return subprocess.check_output(command_args, env=env, shell=shell)


def download_volatility(directory="volatility"):
    """
    Download the latest volatility version.
    """
    if not os.path.isdir("volatility"):
        run(
            "git clone --single-branch ".split() +
            ["https://github.com/volatilityfoundation/volatility.git",
             directory])
    else:
        print("Volatility master has already been downloaded")


def setup_volatility(venv_dir=".vol_venv", volatility_dir="volatility"):
    """
    Create a virtualenv with volatility's dependencies, and also installs
    volatility.
    """
    venv = os.path.join(venv_dir, "bin", "activate")
    if not os.path.isdir(venv_dir):
        run(["virtualenv", venv_dir])
        try:
            run(". {0}; "
                "pip install distorm3 pycrypto; "
                "pip install -e {1}/"
                .format(venv, volatility_dir), shell=True)
        except Exception:
            shutil.rmtree(venv_dir)
            raise
    else:
        print("Volatility virtualenv already set up")


def build_volatility_profile(provider="vmware_fusion",
                             volatility_dir="volatility"):
    """
    Set up the VM to build the volatility profile needed.
    """
    if os.path.isfile(os.path.join(
            volatility_dir, "volatility", "plugins",
            "overlays", "linux", "Ubuntu1404.zip")):
        print("Linux profile for Ubuntu 14.04 already exists.")
        return

    vagrant_status = run("vagrant status profile".split(), printit=False)
    env = dict(os.environ, VOLATILITY_DIR=volatility_dir)
    if "not created" in vagrant_status:
        run("vagrant up profile".split(), env=env)
        run("vagrant provision profile".split(), env=env)
    else:
        run("vagrant up profile --provider={0}".format(provider).split(),
            env=env)

    run("vagrant suspend profile".split(), env=env)


def build_testing_snapshot(
        vmrun="/Applications/VMware Fusion.app/Contents/Library/vmrun",
        provider="vmware_fusion"):
    """
    Build the vmware snapshot needed for testing the volatility plugins.

    :return: The full path to the snapshot vmem
    """
    run("vagrant up testing --provider={0}".format(provider).split())
    with open(".vagrant/machines/testing/{0}/id".format(provider)) as f:
        vmx = f.read()

    if "keys_and_python" in run([vmrun, "listSnapshots", vmx], False):
        run([vmrun, "snapshot", vmx, "keys_and_python"])
    else:
        print("Snapshot for memory testing already exists.")
    return "{0}-Snapshot1.vmem".format(vmx[:-4])


if __name__ == "__main__":
    download_volatility()
    build_volatility_profile()
    build_testing_snapshot()
    setup_volatility()
