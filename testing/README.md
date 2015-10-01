This directory contains a stab at providing automated testing for the `linux_ssh_keys` and `linux_python_strings` plugins.

It generates an image that can test those plugins, and runs the plugins on that image.

It also generates an image to be used to build a profile for the test image.

Currently this only works with VMWare Fusion on OS X.

This currently doesn't do any kind of matrix testing; it only does 64-bit and the latest master version of volatility now, but 32-bit support and other versions of volatility/python/openssh can be added.

It has already found one bug with the `linux_python_strings` plugin (see [issue #3](https://github.com/cyli/volatility_plugins/issues/3)).


Requirements:

- OS X (tested on Yosemite)
- VMWare Fusion (tested on 6.0.6)
- Vagrant (tested on 1.7.4)
- [Vagrant VMWare Fusion integration](https://www.vagrantup.com/vmware)


How to use:

- From the `testing` directory, run `./osx_test.py`
