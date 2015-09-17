CAVEAT: These will only work and have only been tested on a 64-bit Linux system.  A different VType would have to be defined for 32-bit systems.

To use this repo with volatility:

Usage:
1. Install volatility as per instructions
1. `git clone <thisrepo>`
1. `vol.py --plugins=<other_plugin_directories_colon_separated>:<path_to_volatility_plugins> --profile=<profile_name> -f <path_to_memory_dump> <plugin name> -p <PID> --dump-dir .`


# linux_python_strings

Currently the actual implementation of a plugin described at PyCon2015, which
extracts python strings out of the memory of a running python process.

```
vol.py \
    --plugins=<other_plugin_directories_colon_separated>:<path_to_volatility_plugins> \
    --profile=<profile_name> \
    -f <path_to_memory_dump> \
    linux_python_strings -p <PID> --dump-dir .
```

This will print out the PID, task name, and string, but the string is shortened in the middle for printing purposes.

Using --dump-dir will write the strings to a file named `<PID>.<task_name>.strings` in whatever directory you provide as an option.  The strings will be printed in repr'ed form.

# linux_ssh_keys

Plugin which extracts RSA keys from ssh-agent process heaps.

```
vol.py \
    --plugins=<other_plugin_directories_colon_separated>:<path_to_volatility_plugins> \
    --profile=<profile_name> \
    -f <path_to_memory_dump> \
    linux_ssh_keys [--dump-dir .]
```

This will print out the PID, task name, and the filename of the SSH key that
was extracted and dumped in unencrypted PEM format.  By default, the dump
directory will be `/tmp`, and the filenames will have the form
`<PID>.ssh-agent.<key #>`.
