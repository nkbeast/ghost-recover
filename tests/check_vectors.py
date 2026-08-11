import re
import sys

src = open('src/selftest.cpp', 'r', encoding='utf-8').read()

def decode(s):
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            n = s[i + 1]
            if n == 'x' and i + 3 < len(s):
                out.append(int(s[i + 2:i + 4], 16))
                i += 4
            else:
                out.append(ord(n))
                i += 2
        else:
            out.append(ord(c))
            i += 1
    return out

for m in re.finditer(r'\{(\d+), (\d+), "((?:[^"\\]|\\.)*)",', src):
    plain, coded, s = m.group(1), int(m.group(2)), m.group(3)
    actual = len(decode(s))
    if actual != coded:
        print('MISMATCH plain=%s claimed=%d actual=%d' % (plain, coded, actual))
print('scan done')
