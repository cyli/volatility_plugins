import struct
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common  as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False


# Note: this is only if Py_TRACE_REF is not defined
pyobjs_vtype_64 = {
    '_PyStringObject': [
        40,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],  # Py_ssize_t = ssize_t
            'ob_shash': [24, ['long long']],
            'ob_sstate': [32, ['Enumeration',
                               dict(target='int', choices={
                                   0: 'SSTATE_NOT_INTERNED',
                                   1: 'SSTATE_INTERNED_MORTAL',
                                   2: 'SSTATE_INTERNED_IMMORTAL'
                               })]],
            'ob_sval': [36, ['array', 10, ['char']]]
        }],
    }


class _PyStringObject(obj.CType):
    r"""
    A class for python string objects.

    ----
    stringobject.h
    ----

    typedef struct {
        PyObject_VAR_HEAD
        long ob_shash;
        int ob_sstate;
        char ob_sval[1];

        /* Invariants:
         *     ob_sval contains space for 'ob_size+1' elements.
         *     ob_sval[ob_size] == 0.
         *     ob_shash is the hash of the string or -1 if not computed yet.
         *     ob_sstate != 0 iff the string object is in stringobject.c's
         *       'interned' dictionary; in this case the two references
         *       from 'interned' to this object are *not counted* in
         *       ob_refcnt.
         */
    } PyStringObject;

    #define SSTATE_NOT_INTERNED 0
    #define SSTATE_INTERNED_MORTAL 1
    #define SSTATE_INTERNED_IMMORTAL 2

    ----
    object.h - note that _PyObject_HEAD_EXTRA is empty if
    Py_TRACE_REFs is not defined
    ----

    /* PyObject_HEAD defines the initial segment of every PyObject. */
    #define PyObject_HEAD                   \
        _PyObject_HEAD_EXTRA                \
        Py_ssize_t ob_refcnt;               \
        struct _typeobject *ob_type;

    #define PyObject_VAR_HEAD               \
        PyObject_HEAD                       \
        Py_ssize_t ob_size; /* Number of items in variable part */

    """
    def is_valid(self):
        """
        Determine whether the Python string struct is valid - an easy way to
        check is to calculate the hash of the string, and see if it matches
        the `ob_shash`.

        On Python 2.7, the hash function used is FNV.

        This assumes that the python version volatility is using matches the
        python version of the memory dump, because it uses the `hash()`
        function to compute the hash.
        """
        return (self.ob_sstate.v() in self.ob_sstate.choices.keys() and
                self.ob_type.is_valid() and
                self.ob_refcnt > 0 and self.ob_refcnt < 1e6 and
                # skip empty strings and strings that are too big
                self.ob_size > 0 and self.ob_size <= 1e6 and
                (self.ob_shash == -1 or  # hash has not been computed yet
                 self.ob_shash == hash(self.string)))

    @property
    def string(self):
        sval_offset, _ = self.members['ob_sval']
        return self.obj_vm.zread(self.obj_offset + sval_offset,
                                 self.ob_size)


class PythonStringTypes(obj.ProfileModification):
    """
    Profile modifications for Python string types.  Only Linux and Mac OS,
    on 64-bit systems, are supported right now.
    """
    conditions = {"os": lambda x: x in ["linux", "mac"],
                  "memory_model": lambda x: x == "64bit"}

    def modification(self, profile):
        """
        Add python string overlays to the profile's vtypes.
        """
        profile.vtypes.update(pyobjs_vtype_64)
        profile.object_classes.update({"_PyStringObject": _PyStringObject})


def find_python_string(string, task, memory64bit=True):
    """
    Given a string to find, and a task to find it in, searches the task's heap
    for that string and attempts to map it to a Python string struct.
    """
    addresses = task.search_process_memory([string], heap_only=True)
    addr_space = task.get_process_address_space()
    sval_offset = addr_space.profile.get_obj_offset(
        "_PyStringObject", "ob_sval")

    for address in addresses:
        # the string is at the end of the struct, subtract the offset of the
        # rest of the struct
        py_string = obj.Object("_PyStringObject",
                               offset=address - sval_offset,
                               vm=addr_space)
        print repr(addr_space.zread(address, len(string)+50))
        print repr(addr_space.zread(address - 64, 64))
        print dir(py_string.ob_sval)

        if py_string.is_valid():
            yield py_string


def brute_force_search_heap(task):
    addr_space = task.get_process_address_space()

    for vma in task.get_proc_maps():
        if not (vma.vm_start <= task.mm.start_brk and
                vma.vm_end >= task.mm.brk):
            continue

        for offset in xrange(vma.vm_start, vma.vm_end, 8):
            py_string = obj.Object("_PyStringObject",
                                   offset=offset,
                                   vm=addr_space)
            if offset % 1024 == 0:
                print "{0} of {1}".format(offset, vma.vm_end - vma.vm_start)

            if py_string.is_valid():
                yield py_string


class linux_python_strings(linux_pslist.linux_pslist):
    """
    Pull python strings from a process's heap.
    """
    def calculate(self):
        """
        Find the tasks that are actually python processes.  May not
        necessarily be called "python", but the executable is python.
        """
        if not has_yara:
            debug.error(
                "Please install Yara from https://plusvic.github.io/yara/")

        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            code_area = [vma for vma in task.get_proc_maps()
                         if (task.mm.start_code >= vma.vm_start and
                         task.mm.end_code <= vma.vm_end)]
            if code_area and 'python' in code_area[0].vm_name(task):
                for py_string in brute_force_search_heap(task):
                    yield task, py_string

                # for py_string in find_python_string("subprocess", task):
                #     yield task, py_string

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                         ("Name", str),
                         ("string", str)],
                        self.generator(data))

    def generator(self, data):
        for task, py_string in data:
            yield (0, [int(task.pid),
                       str(task.comm),
                       py_string.string])
