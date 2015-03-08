"""
Plugin to find python strings within process heaps.
"""

from itertools import groupby
import re
import struct

from volatility import debug as debug
from volatility import obj as obj
from volatility.plugins.linux import common as linux_common
from volatility.plugins.linux import pslist as linux_pslist
from volatility.renderers import TreeGrid


# Note: It doesn't actually matter if Py_TRACE_REF is defined, that just means
# there are more structures at the beginning, which we don't care about
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
        """
        Read the string from memory, because `ob_sval` is a
        :class:`volatility.obj.NativeType.Array` object, which is slow to
        iterate through to turn into a string.
        """
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


def brute_force_search(addr_space, obj_type_string, start, end, step_size=1):
    """
    Brute-force search an area of memory for a given object type.  Returns
    valid types as a generator.
    """
    for offset in xrange(start, end, step_size):
        found_object = obj.Object(obj_type_string,
                                  offset=offset,
                                  vm=addr_space)
        if found_object.is_valid():
            yield found_object


def _brute_force_5_strings(addr_space, heaps):
    """
    Search the heaps 5K at a time until 5 strings are found.  Why 5?
    Arbitrary.  Just so long as it's not 1, which may be a false positive.
    """
    bfed_strings = []
    chunk_size = 1024 * 5
    for heap_vma in heaps:
        for chunk_start in xrange(heap_vma.vm_start,
                                  heap_vma.vm_end,
                                  chunk_size):
            bfed_strings.extend(list(brute_force_search(
                addr_space=addr_space,
                obj_type_string="_PyStringObject",
                start=chunk_start,
                end=chunk_start + chunk_size - 1,
                step_size=4)))
            if len(bfed_strings) >= 5:
                return bfed_strings


def find_python_strings(task):
    """
    Attempt to find python strings in the heap.  Brute-force search is pretty
    slow, so we are going to optimize a bit.

    The `ob_type` of a PyObjString is a pretty involved struct, so we are not
    searching on that pattern, but all Python strings should point to the
    same type in memory.

    We will brute-force search until a couple of strings are found.  We want
    to make sure that they all point to the same type in memory.  Once we have
    a good guess at where that type resides in memory, we can search
    specifically for that address value in the heap and use that as a hint as
    to where there might be a PyObjString.
    """
    addr_space = task.get_process_address_space()
    likely_strings = _brute_force_5_strings(addr_space, get_heaps(task))
    likely_strings_by_type = {
        pointer: list(strings) for pointer, strings
        in groupby(likely_strings, lambda pystr: pystr.ob_type)
    }

    debug.info("Found {0} possible string _typeobject pointer(s): {1}".format(
        len(likely_strings_by_type),
        ", ".join([
            "0x{0:012x} ({1})".format(pointer.v(), len(strings))
            for pointer, strings in likely_strings_by_type.iteritems()])))

    memory_model = addr_space.profile.metadata.get('memory_model', '32bit')
    pack_format = "I" if memory_model == '32bit' else "Q"
    offset = addr_space.profile.get_obj_offset("_PyStringObject", "ob_type")

    str_types_as_bytes = [struct.pack(pack_format, pointer.v())
                          for pointer in likely_strings_by_type]

    for address in task.search_process_memory(str_types_as_bytes,
                                              heap_only=True):
        # We will find the likely_strings again, but that's ok
        py_string = obj.Object("_PyStringObject",
                               offset=address - offset,
                               vm=addr_space)
        if py_string.is_valid():
            yield py_string


def get_heaps(task):
    """
    Given a task, return the mapped sections corresponding to that task's
    heaps.
    """
    for vma in task.get_proc_maps():
        if (vma.vm_start <= task.mm.start_brk and vma.vm_end >= task.mm.brk):
            yield vma


class linux_python_strings(linux_pslist.linux_pslist):
    """
    Pull python strings from a process's heap.
    """
    def __init__(self, config, *args, **kwargs):
        """
        Add a configuration for checking strings, basically a regex to check
        for.
        """
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option(
            'regex', default='None', type='string',
            help='Provide a regex: only return strings that match the regex.')

    def calculate(self):
        """
        Find the tasks that are actually python processes.  May not
        necessarily be called "python", but the executable is python.
        """
        linux_common.set_plugin_members(self)

        regex = None
        if self._config.regex:
            regex = re.compile(self._config.regex)

        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            code_area = [vma for vma in task.get_proc_maps()
                         if (task.mm.start_code >= vma.vm_start and
                         task.mm.end_code <= vma.vm_end)]
            if code_area and 'python' in code_area[0].vm_name(task):
                for py_string in find_python_strings(task):
                    if regex is None or regex.match(py_string.string):
                        yield task, py_string

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                         ("Name", str),
                         ("Size", int),
                         ("String", str)],
                        self.generator(data))

    def generator(self, data):
        for task, py_string in data:
            yield (0, [int(task.pid),
                       str(task.comm),
                       int(py_string.ob_size),
                       py_string.string])
