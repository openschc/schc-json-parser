"""
.. module: gen_base_import
   :platform: Micropython/Python
   :synopsis: Common import file providing differentiation between python and micropython

"""
# Import all external modules with proper try/except in order to allow
# for code running on both Micropython and Python
# Import some internal modules (fake/temporary versions)

import sys

import time
import json
from collections import namedtuple
import random as random
import struct
import socket

# --- default imports

from SCHCPParserTool.gen_bitarray import BitBuffer
from SCHCPParserTool.frag_rcs_crc32 import get_mic, get_mic_size

def b2hex(b):
    """This function replace the bytes.hex() function provided in Python3.5 and later

    .. note::

       Micropython (Python 3.4) doesn't support bytes.hex().

    Args:
       b (bytes): the byte chain to convert to hexadecimal representation

    Returns:
       str : The string representation of the converted hex

    Example:
    
    >>> print b2hex(b'123')
    '313233'
    """
    return "".join(["%02x"%_ for _ in b])
