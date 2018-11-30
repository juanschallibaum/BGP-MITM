#!/usr/bin/python

import sys

s = sys.argv[1]
sx = "\n" + r"\x" + r"\x".join(s[n : n+2] for n in range(0, len(s), 2))
print(sx)