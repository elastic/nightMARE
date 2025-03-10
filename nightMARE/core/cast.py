# coding: utf-8

import functools
import base64


u64 = lambda x: int.from_bytes(x[0:8], "little")
u32 = lambda x: int.from_bytes(x[0:4], "little")
u16 = lambda x: int.from_bytes(x[0:2], "little")
u8 = lambda x: int.from_bytes(x[0:1], "little")

p64 = lambda x: x.to_bytes(8, "little")
p32 = lambda x: x.to_bytes(4, "little")
p16 = lambda x: x.to_bytes(2, "little")
p8 = lambda x: x.to_bytes(1, "little")
