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

"""Helpers for working with BPF maps from Python.
"""

from ctypes import *

from .bpf import *


class Map:
    """Pinned BPF map. Can be used as context manager in a `with` statement."""

    def __init__(self, pin_path: bytes, map_type: int):
        """Open a BPF map pinned at `pin_path`.
        :param map_type: Expected map type. One of bpf.BPF_MAP_TYPE_*
        """
        self.fd = bpf_obj_get(pin_path)
        try:
            info = get_map_info_by_fd(self.fd)
            if info.type != map_type:
                raise BpfError("Map type mismatch")
            self.map_type = map_type
            self.key_size = info.key_size
            self.value_size = info.value_size
        except:
            close(self.fd)
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self.fd > 0:
            close(self.fd)
            self.fd = -1

    def lookup(self, key, value) -> bool:
        """Retrieve a value from the map. `key` and `value` must be appropriate ctypes types.
        :return: True if the element was found, otherwise false.
        """
        if not self._verify_arg_size(sizeof(key), sizeof(value)):
            raise BpfError("Invalid key/value size")
        return map_lookup_elem(self.fd, key, value)

    def _verify_arg_size(self, key_size: int, value_size: int):
        if self.map_type == BPF_MAP_TYPE_PERCPU_HASH or self.map_type == BPF_MAP_TYPE_ARRAY:
            return key_size >= self.key_size and value_size >= (self.value_size * os.cpu_count())
        else:
            return key_size >= self.key_size and value_size >= self.value_size
