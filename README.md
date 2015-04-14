Initial commit is the actual implementation of a plugin described at PyCon2015

Usage:

1. Install volatility as per instructions
1. `git clone <thisrepo>`
1. `vol.py --plugins=<other_plugin_directories_colon_separated>:<path_to_volatility_plugins> --profile=<profile_name> -f <path_to_memory_dump> linux_python_strings -p <PID> --dump-dir .`

This will print out the PID, task name, and string, but the string is shortened in the middle for printing purposes.

Using `--dump-dir` will write the strings to a file named `<PID>.<task_name>.strings` in whatever directory you provide as an option.  The strings will be printed in repr'ed form.

CAVEAT: this will only work and has only been tested on a 64-bit Linux system.  A different VType would have to be defined for 32-bit systems.
