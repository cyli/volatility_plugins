#!/usr/bin/env python

"""
Verify that the volatility plugins work with VMWare (Fusion on OSX)
This general should technically also work with VMWare for windows or linux,
but the paths are different and must be specified.

VMWare was chosen because snapshotting it produces a raw memory dump, which is
nice and easy.

See https://www.vmware.com/support/developer/vix-api/vix111_vmrun_command.pdf
"""
from __future__ import print_function

import glob
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

    Returns the environment, post-virtualenv activation, as a dictionary so
    that sourcing the virtualenv doesn't have to happen again, as it gets
    tricky
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

    env = run(". {0}; env".format(venv), printit=False, shell=True)
    return dict([line.split("=", 1) for line in env.split("\n")
                 if line.strip()])


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

    vagrant_status = run("vagrant status profile", printit=False)
    env = dict(os.environ, VOLATILITY_DIR=volatility_dir)
    if "not created" in vagrant_status:
        run("vagrant up profile", env=env)
        run("vagrant provision profile", env=env)
    else:
        run("vagrant up profile --provider={0}".format(provider).split(),
            env=env)

    run("vagrant suspend profile", env=env)


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

    if "keys_and_python" not in run([vmrun, "listSnapshots", vmx], False):
        run([vmrun, "snapshot", vmx, "keys_and_python"])
    else:
        print("Snapshot for memory testing already exists.")
    return "{0}-Snapshot1.vmem".format(vmx[:-4])


def _contents(filename):
    with open(filename) as f:
        return f.read()


def test_ssh_keys(env, snapshot):
    """
    Run the SSH-keys plugin to extract the keys from the given snapshot, and
    assert whether they are the same keys as were generated.
    """
    run("vol.py --plugins=profiles:../plugins "
        "--profile=LinuxUbuntu1404x64 -f {0} linux_ssh_keys --dump-dir=."
        .format(snapshot), env=env, shell=True)
    keys = glob.glob("*.ssh-agent.*")
    expected = {_contents(k): k for k in glob.glob("id_rsa.*")
                if not k.endswith("passwd")}

    assert len(keys) == len(expected), (
        "There should be {0} ssh keys found.".format(len(expected)))
    assert len(set([k.split(".", 1)[0] for k in keys])) == 1, (
        "There should be just one ssh-agent process.")

    for k in keys:
        match = expected.pop(_contents(k), None)
        assert match is not None, "{0} not an expected key.".format(k)

    assert len(expected) == 0, "{0} were not found in memory".format(
        ", ".join(expected.values()))

    print("All the expected keys were found.")


if __name__ == "__main__":
    download_volatility()
    build_volatility_profile()
    snapshot = build_testing_snapshot()
    env = setup_volatility()
    test_ssh_keys(env, snapshot)
