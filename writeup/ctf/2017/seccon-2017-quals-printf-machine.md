---
layout: post
alias: "/blog/2017/12/10/seccon-2017-quals-printf-machine/"
title: "SECCON 2017 Online CTF: printf machine"
date: "2017-12-10T15:18:40+09:00"
tags: [ "ctf", "writeup", "seccon", "seccon-quals", "rev", "interpreter", "printf", "format-string-attack", "esolang", "z3" ]
"target_url": [ "https://ctftime.org/event/512/" ]
---

## problem

An interpreter of format strings and the script file are given.
Find the string that the script accepts.

## solution

Disasm the script and give the result to a SMT solver.

The interpreter has $32$ byte data for target-level, internally.
But format-strings requires: prepare adds to the data, to write, `1$` $\dots$ `32$`; and scatter and zero-ext `char`s to `int64_t`s, to read, `33$` $\dots$ `64$`.
The input is stored at $16 \dots 32$, and the result flag is $15$.

In the script, you can only do add/sum, without loop. Hence the class of computability is very weak, and easily translated to formulas for SMT solver.

## implementation

``` python
#!/usr/bin/env python2
import re
import sys
import z3

def memory(addr, write=False):
    assert 1 <= addr <= 64
    assert write == (addr <= 32)
    i = (addr - 1) % 32
    if i >= 16:
        name = 'flag[%d]' % (i - 16)
    elif i == 15:
        name = 'result'
    else:
        name = 'r%d' % (i + 1)
    return name

def parse_op(fmt):
    m = re.match(r'^%2\$\*(\d+)\$s$', fmt)
    if m:
        addr = int(m.groups()[0])
        return { 'cmd': '*s', 'var': memory(addr) }
    m = re.match(r'^%(\d+)\$hhn$', fmt)
    if m:
        addr = int(m.groups()[0])
        return { 'cmd': 'hhn', 'var': memory(addr, write=True) }
    m = re.match(r'^%2\$(\d+)s$', fmt)
    if m:
        value = int(m.groups()[0])
        assert 0 < value < 256
        return { 'cmd': 's', 'var': str(value) }
    if fmt == '%1$s':
        return { 'cmd': 'bool', 'var': 'bool(r1)' }
    assert False

# prepare z3
solver = z3.Solver()
env = {}
for i in range(15):
    env['r%d' % (i + 1)] = 0
flag = []
for i in range(16):
    name = 'flag[%d]' % i
    env[name] = z3.BitVec(name, 8)
    flag += [ env[name] ]
    solver.add(32 <= flag[i])
    solver.add(flag[i] <= 126)

# read and interpret the code
with open('default.fs') as fh:
    for line in fh:
        op = [ parse_op('%' + fmt) for fmt in line.rstrip()[1 :].split('%') ]

        if op[0]['cmd'] == 'hhn':
            env[op[0]['var']] = 0
            print '[*] disas:', op[0]['var'], '= 0'
            op = op[1 :]

        if len(op) == 0:
            pass

        elif len(op) == 2:
            if op[0]['cmd'] == 'bool':
                assert op[0]['var'] == 'bool(r1)' and op[1]['cmd'] == 'hhn'
                solver.add(env['r1'] == 0)
                env[op[1]['var']] = 0
            else:
                assert op[0]['cmd'][-1] == 's' and op[1]['cmd'] == 'hhn'
                env[op[1]['var']] = env[op[0]['var']]
            print '[*] disas:', op[1]['var'], '=', op[0]['var']

        elif len(op) == 3:
            print '[*] disas:', op[2]['var'], '=', op[0]['var'], '+', op[1]['var']
            assert op[0]['cmd'][-1] == op[1]['cmd'][-1] == 's' and op[2]['cmd'] == 'hhn'
            if op[2]['var'] == 'result':
                assert op[0]['var'] == 'result'
                # reduced
            else:
                if op[1]['cmd'] == '*s':
                    env[op[2]['var']] = env[op[0]['var']] + env[op[1]['var']]
                else:
                    env[op[2]['var']] = env[op[0]['var']] + int(op[1]['var'])

        else:
            assert False

    print '[*] disas:', 'assert result == 0'
result = solver.check()
assert result == z3.sat
model = solver.model()
for i in range(16):
    flag[i] = chr(model[flag[i]].as_long())
flag = ''.join(flag)
print '[+] flag:', flag
```
