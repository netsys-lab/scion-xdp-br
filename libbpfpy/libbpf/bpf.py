# Copyright (c) 2022 Lars-Christian Schulz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Python wrapper around some libbpf functions.
"""
import os
from ctypes import *
from ctypes.util import find_library

_libc = CDLL(find_library("c"))
_libbpf = CDLL(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../build/libbpf.so.0.6.0")),
    use_errno=True
)

class BpfError(Exception):
    pass

def _check_bpf_err(result, func, args):
    if result != 0:
        raise BpfError(f"BPF: Error in {func}")
    return result

####################
## BPF_MAP_TYPE_* ##
####################

BPF_MAP_TYPE_UNSPEC = 0
BPF_MAP_TYPE_HASH = 1
BPF_MAP_TYPE_ARRAY = 2
BPF_MAP_TYPE_PERCPU_HASH = 5
BPF_MAP_TYPE_PERCPU_ARRAY = 6

###########
## close ##
###########

_close = _libc.close
_close.restype = c_int
_close.argtypes = [c_int]

def close(fd: int) -> int:
    return _close(fd)

####################
## bpf_object_get ##
####################

def _check_obj_get(result, func, args):
    if result < 0:
        raise FileNotFoundError(f"Cannot open file {str(args[0], encoding='utf8')}")
    return result

_bpf_obj_get = _libbpf.bpf_obj_get
_bpf_obj_get.restype = c_int
_bpf_obj_get.argtypes = [c_char_p]
_bpf_obj_get.errcheck = _check_obj_get

def bpf_obj_get(path: bytes) -> int:
    return _bpf_obj_get(path)

############################
## bpf_obj_get_info_by_fd ##
############################

class bpf_map_info(Structure):
    _fields_ = [
        ("type", c_uint32),
        ("id", c_uint32),
        ("key_size", c_uint32),
        ("value_size", c_uint32),
        ("max_entries", c_uint32),
        ("map_flags", c_uint32),
        ("name", c_char * 16),
        ("ifindex", c_uint32),
        ("btf_vmlinux_value_type_id", c_uint32),
        ("netns_dev", c_uint32),
        ("netns_ino", c_uint32),
        ("btf_id", c_uint32),
        ("btf_key_type_id", c_uint32),
        ("btf_value_type_id", c_uint32),
    ]

_bpf_obj_get_info_by_fd = _libbpf.bpf_obj_get_info_by_fd
_bpf_obj_get_info_by_fd.restype = c_int
_bpf_obj_get_info_by_fd.argtypes = [c_int, POINTER(bpf_map_info), POINTER(c_uint)]
_bpf_obj_get_info_by_fd.errcheck = _check_bpf_err

def get_map_info_by_fd(fd: int) -> bpf_map_info:
    info = bpf_map_info()
    info_len = c_uint(sizeof(info))
    _bpf_obj_get_info_by_fd(fd, byref(info), byref(info_len))
    if (info_len.value != sizeof(info)):
        raise BpfError("BPF object is not a map")
    return info

#########################
## bpf_map_lookup_elem ##
#########################

_bpf_map_lookup_elem = _libbpf.bpf_map_lookup_elem
_bpf_map_lookup_elem.restype = c_int
_bpf_map_lookup_elem.argtypes = [c_int, c_void_p, c_void_p]

def map_lookup_elem(fd: int, key, value) -> bool:
    """Search for en element in the map and return its value in `value`.
    :return: True if the element was found, otherwise false.
    """
    err =  _bpf_map_lookup_elem(fd, byref(key), byref(value))
    if err:
        if get_errno() == 2: # ENOENT
            return False
        else:
            raise BpfError("BPF: Error in map_lookup_elem")
    return True
