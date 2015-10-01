CAVEAT: These will only work and have only been tested on a 64-bit Linux system.  A different VType would have to be defined for 32-bit systems.

Usage instructions below assume that volatility is already installed with dependencies.

*Only the latest version (not the released versions 2.4 or 2.4.1, but actual latest master) is supported.*

## linux_python_strings

Originally [described in a presentation at PyCon2015](https://www.youtube.com/watch?v=tMKXcc2-xO8), this plugin extracts python strings out of the memory of a running python process.

```
vol.py \
    --plugins=profiles:<other_plugin_directories_colon_separated>:<path_to_this_repo>/plugins \
    --profile=<profile_name> \
    -f <path_to_memory_dump> \
    linux_python_strings -p <PID> --dump-dir .
```

This will print out the PID, task name, and string, but the string is shortened in the middle for printing purposes.

Using `--dump-dir` will write the strings to a file named `<PID>.<task_name>.strings` in whatever directory you provide as an option.  The strings will be printed in `repr`'ed form.

## linux_ssh_keys

Plugin which extracts RSA keys from ssh-agent process heaps.

```
vol.py \
    --plugins=profiles:<other_plugin_directories_colon_separated>:<path_to_this_repo>/plugins \
    --profile=<profile_name> \
    -f <path_to_memory_dump> \
    linux_ssh_keys [--dump-dir .]
```

This will print out the PID, task name, and the filename of the SSH key that
was extracted and dumped in unencrypted PEM format.  By default, the dump
directory will be `/tmp`, and the filenames will have the form
`<PID>.ssh-agent.<key #>`.

Currently only tested with unencrypted SSH keys.


## Testing

Please see the README and code in the `testing` directory.  It automates generating a testing memory image, as well as a testing profile.
