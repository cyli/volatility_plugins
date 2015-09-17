"""
Plugin to find python strings within process heaps.
"""
import struct

try:
    from cryptography.hazmat.backends.openssl.backend import backend
except ImportError:
    backend = None

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    rsa = None

from volatility import obj as obj
from volatility.plugins.linux import common as linux_common
from volatility.plugins.linux import pslist as linux_pslist
from volatility.renderers import TreeGrid


openssl_vtypes_64 = {
    '_BIGNUM': [
        24,
        {
            # BaseObject has an instance method 'd'
            'd_': [0, ['pointer',
                       ['array', lambda x: x.dmax, ['long long']]]],
            'top': [8, ['int']],
            'dmax': [12, ['int']],
            'neg': [16, ['int']],
            'flags': [20, ['Enumeration',
                           dict(target='int', choices={
                               1: 'BN_FLG_MALLOCED',
                               2: 'BN_FLG_STATIC_DATA',
                               4: 'BN_FLG_CONSTTIME'
                           })]],
        }],
    '_RSA': [
        96,
        {
            'pad': [0, ['int']],
            '__ignore': [4, ['int']],  # GCC-introduced packing padding
            'version': [8, ['long long']],
            'meth': [16, ['pointer', ['void']]],
            'engine': [24, ['pointer', ['void']]],
            'n': [32, ['pointer', ['_BIGNUM']]],
            'e': [40, ['pointer', ['_BIGNUM']]],
            # BaseObject has an instance method 'd'
            'd_': [48, ['pointer', ['_BIGNUM']]],
            # These are all optimizations and ssh-agent may not set these
            'p': [56, ['pointer', ['_BIGNUM']]],
            'q': [64, ['pointer', ['_BIGNUM']]],
            'dmp1': [72, ['pointer', ['_BIGNUM']]],
            'dmq1': [80, ['pointer', ['_BIGNUM']]],
            'iqmp': [88, ['pointer', ['_BIGNUM']]]
            # We don't care about the rest
        }]
    }


openssh_vtypes_64 = {
    '_SSH_Agent_RSA_Key': [
        24,
        {
            'type': [0, ['Enumeration',
                         dict(target='int', choices={
                             # we only care about RSA
                             0: 'KEY_RSA1',
                             1: 'KEY_RSA',
                             2: 'KEY_DSA',
                             3: 'KEY_ECDSA',
                             4: 'KEY_RSA_CERT',
                             5: 'KEY_DSA_CERT',
                             6: 'KEY_ECDSA_CERT',
                             7: 'KEY_RSA_CERT_V00',
                             8: 'KEY_DSA_CERT_V00',
                             9: 'KEY_UNSPEC'
                         })]],
            'flags': [4, ['Enumeration',
                          dict(target='int', choices={
                              0: 'normal',
                              1: 'KEY_FLAG_EXT'
                          })]],
            'rsa': [8, ['pointer', ['_RSA']]],
            'dsa': [16, ['pointer', ['_RSA']]]
        }]
    }


class _BIGNUM(obj.CType):
    r"""
    in openssl/bn/bn.h

    struct bignum_st
        {
        BN_ULONG *d;    /* Pointer to an array of 'BN_BITS2' bit chunks. */
        int top;    /* Index of last used d +1. */
        /* The next are internal book keeping for bn_expand. */
        int dmax;   /* Size of the d array. */
        int neg;    /* one if the number is negative */
        int flags;
        };

    /* assuming long is 64bit - this is the DEC Alpha
    * unsigned long long is only 64 bits :-(, don't define
    * BN_LLONG for the DEC Alpha */
    #define BN_ULLONG   unsigned long long
    #define BN_BYTES    8
    #define BN_BITS2    64

    /* This is where the long long data type is 64 bits, but long is 32.
     * For machines where there are 64bit registers, this is the mode to use.
     * IRIX, on R4000 and above should use this mode, along with the relevant
     * assembler code :-).  Do NOT define BN_LLONG.
     */
    #define BN_ULONG    unsigned long long
    #define BN_BYTES    8
    #define BN_BITS2    64

    // 32-bit
    #define BN_ULONG    unsigned int
    #define BN_BYTES    4
    #define BN_BITS2    32

    #define BN_FLG_MALLOCED     0x01
    #define BN_FLG_STATIC_DATA  0x02
    #define BN_FLG_CONSTTIME    0x04
        /* avoid leaking exponent information through timing,
         * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
         * BN_div() will call BN_div_no_branch,
         * BN_mod_inverse() will call BN_mod_inverse_no_branch.
         */
    """
    def is_valid(self):
        return (self.d_.is_valid() and
                self.top >= 0 and self.top <= self.dmax and
                self.dmax >= 0 and
                self.neg in (0, 1) and
                self.flags.v() in self.flags.choices.keys())

    def value(self):
        # read it into a local bn value
        binary = self.obj_vm.zread(self.d_.v(), self.dmax * 8)
        bn_ptr = backend._lib.BN_bin2bn(binary, len(binary),
                                        backend._ffi.NULL)
        # now turn it into an int
        return backend._bn_to_int(bn_ptr)


class _RSA(obj.CType):
    r"""
    From openssl/include/openssl/rsa.h

    struct rsa_st
        {
        int pad;
        long version;
        const RSA_METHOD *meth;
        /* functional reference if 'meth' is ENGINE-provided */
        ENGINE *engine;
        BIGNUM *n;              // public modulus
        BIGNUM *e;              // public exponent
        BIGNUM *d;              // private exponent
        BIGNUM *p;              // secret prime factor
        BIGNUM *q;              // secret prime factor
        BIGNUM *dmp1;           // d mod (p-1)
        BIGNUM *dmq1;           // d mod (q-1)
        BIGNUM *iqmp;           // q^-1 mod p
        // ...
        };

    in openssl/include/openssl/ossl_typ.h, which is included in rsa.h:
    typedef struct rsa_st RSA;

    Some combination of (n, e, d), or (n, e, p, q), or (n, e, dmp1 dmq1, iqmp)
    must be needed for this to be a valid key.
    """
    _bignums = ('n', 'e', 'd_', 'p', 'q', 'dmp1', 'dmq1', 'iqmp')

    def is_valid(self):
        # Check the pointers
        if not all([getattr(self, ptr).is_valid() for ptr in self._bignums]):
            return False

        nums = {k: getattr(self, k).dereference() for k in self._bignums}

        if not all([num.is_valid() for num in nums.values()]):
            return False

        for k in nums:
            nums[k] = nums[k].value()

        print nums
        return (
            rsa._check_public_key_components(e=nums['e'], n=nums['n']) and
            rsa._check_private_key_components(
                p=nums['p'],
                q=nums['q'],
                private_exponent=nums['d_'],
                dmp1=nums['dmp1'],
                dmq1=nums['dmq1'],
                iqmp=nums['iqmp'],
                public_exponent=nums['e'],
                modulus=nums['n'])
        )

    @property
    def private_key_obj(self):
        return rsa.RSAPrivateNumbers(
            p=self.p.dereference().value(),
            q=self.q.dereference().value(),
            d=self.d_.dereference().value(),
            dmp1=self.dmp1.dereference().value(),
            dmq1=self.dmq1.dereference().value(),
            iqmp=self.iqmp.dereference().value(),
            public_numbers=rsa.RSAPublicNumbers(
                e=self.e.dereference().value(),
                n=self.n.dereference().value()))


class _SSH_Agent_Key(obj.CType):
    r"""
    in openssh/sshkey.h  (also typedef'ed as openssh/key.h Key)

    struct sshkey {
        int type;
        int flags;
        RSA *rsa;
        DSA *dsa;
    };

    enum types {
        KEY_RSA1,
        KEY_RSA,
        KEY_DSA,
        KEY_ECDSA,
        KEY_RSA_CERT,
        KEY_DSA_CERT,
        KEY_ECDSA_CERT,
        KEY_RSA_CERT_V00,
        KEY_DSA_CERT_V00,
        KEY_UNSPEC
    };

    /* key is stored in external hardware */
    #define KEY_FLAG_EXT        0x0001
    """
    def is_valid(self):
        """
        If it's an RSA key, it should be one of the RSA key types (or
        KEY_UNSPEC).  In which case the DSA pointer should be null, and
        the RSA pointer should point to an RSA object.

        The reverse should be true for DSA, but that is not supported yet.
        """
        return (self.type.v() in (0, 1, 4, 7, 9) and
                self.dsa.v() == 0 and
                self.rsa.is_valid() and
                self.rsa.dereference().is_valid())


class SSLSSHTypes(obj.ProfileModification):
    """
    Profile modifications for SSL and SSh types.  Only Linux and Mac OS,
    on 64-bit systems, are supported right now.
    """
    conditions = {"os": lambda x: x in ["linux", "mac"],
                  "memory_model": lambda x: x == "64bit"}

    def modification(self, profile):
        """
        SSL and SSH overlays to profile.
        """
        profile.vtypes.update(openssl_vtypes_64)
        profile.vtypes.update(openssh_vtypes_64)
        profile.object_classes.update({
            "_BIGNUM": _BIGNUM,
            "_RSA": _RSA,
            "_SSH_Agent_RSA_Key": _SSH_Agent_Key
        })


def find_ssh_key(task):
    """
    Attempt to find RSA ssh agent keys on the heap.  Since we are looking for
    RSA keys only, try to build an initial string to search for.  There will
    be a lot of matches, but this should be faster than brute-force scanning.
    """
    possible_strings = [
        struct.pack('ii', key_type, 0)
        for key_type in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)]

    addr_space = task.get_process_address_space()

    key = obj.Object("_SSH_Agent_RSA_Key", offset=139733834194960,
                     vm=addr_space)
    if key.is_valid():
        yield key

    # for addr in task.search_process_memory(possible_strings):
    #     key = obj.Object("_SSH_Agent_RSA_Key", offset=addr, vm=addr_space)
    #     if key.is_valid():
    #         yield key


class linux_ssh_keys(linux_pslist.linux_pslist):
    """
    Get SSH keys from process heaps.
    """
    def calculate(self):
        """
        Find the tasks that are ssh-agent processes, then search for ssh keys.
        """
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            if 'ssh-agent' in str(task.comm):
                for key in find_ssh_key(task):
                    yield task, key

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                         ("Name", str),
                         ("Keys found", int)],
                        self.generator(data))

    def generator(self, data):
        for task, key in data:
            yield (0, [int(task.pid),
                       str(task.comm),
                       key.obj_offset])
