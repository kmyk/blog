---
layout: post
redirect_from:
  - /writeup/ctf/2016/twctf-2016-lights-out/
  - /blog/2016/09/05/twctf-2016-lights-out/
date: "2016-09-05T14:31:00+09:00"
tags: [ "ctf", "writeup", "ppc", "mmactf", "twctf", "dp", "matrix" ]
"target_url": [ "https://score.ctf.westerns.tokyo/problems/13" ]
---

# Tokyo Westerns/MMA CTF 2nd 2016: Lights Out!

とても時間を取られた。指数でしかできない気がしていたのが原因。z3とかで無理矢理やろうとしたけど駄目だった。

## solution

Lights out for $768 \times 768$ cells.
DP + linear algebra.
$O(HW \cdot \min \\{ H, W \\})$.

At first, think the $O(HW \cdot 2^{\min \\{ H, W \\}})$ solution with DP.
If you are fix whether do flip or not, for each cell of the top $2$ rows, then whether sholud flip or not for other cells are uniquely determined.
There are $2^{2W}$ ways to flip top $2$ rows, and flipping other cells takes $O(HW)$. The total is $O(HW \cdot 2^{\min \\{ H, W \\}})$.

We want to construct the way to flip the top $2$ rows, for above DP.
If you flip at one cell, it affects the bottom $2$ rows.
Thinking the function about this, it is $f : 2W \to 2^{2W}$ or a matrix $f : 2W \times 2W \to 2$.
Also let vector $y : 2W \to 2$ be the DP-ed cells without flipping any cells in top $2$ rows.
Then we can get flag with $x : 2W \to 2$ such that $fx \equiv y \pmod 2$.
One of this $x$ is obtained using Gaussian elimination, even if $f$ may be singular.

## similar problems

-   EXTENDED LIGHTS OUT <http://poj.org/problem?id=1222>
    -   蟻本に載ってたやつはこれらしい
-   Tile Puzzle <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2140>

## implementation

``` python
#!/usr/bin/env python3
import sys

import subprocess
import json
def load_level(level): #=> dict
    assert level in [ 'easy', 'normal', 'lunatic' ]
    js = 'console.log(JSON.stringify(require("./data.js").data.' + level + '))'
    proc = subprocess.run(['nodejs', '-e', js], stdout=subprocess.PIPE)
    return json.loads(proc.stdout.decode())
import tempfile
import os
def submit_solution(url, level, clicked):
    fh = tempfile.NamedTemporaryFile(suffix='.json', mode='w', delete=False)
    json.dump({ 'level': level, 'clicked': clicked }, fh)
    fh.close()
    subprocess.run(['curl', '-v', url, '-H', 'Content-Type: application/json', '-d', '@' + fh.name])
    os.unlink(fh.name)
    return

def encode_field(s, h, w):
    return [ [ s[y*w+x] == '1' for x in range(w) ] for y in range(h) ]
def decode_field(f):
    return ''.join(map(lambda p: '01'[p], sum(f, [])))
def empty_field(h, w):
    return [ [ False for x in range(w) ] for y in range(h) ]
def get_size(f):
    h = len(f)
    w = len(f[0])
    # assert all(map(lambda row: len(row) == w, f))
    return h, w
def xor_field(a, b):
    assert get_size(a) == get_size(b)
    h, w = get_size(a)
    return [ [ a[y][x] != b[y][x] for x in range(w) ] for y in range(h) ]
def xor_at(field, y, x): # destructive
    field[y][x] = not field[y][x]
def flip_at(field, y, x): # destructive
    h, w = get_size(field)
    for dy, dx in [ (0,2), (1,1), (2,0), (1,-1), (0,-2), (-1,-1), (-2,0), (-1,1) ]:
        ny = y + dy
        nx = x + dx
        if 0 <= ny < h and 0 <= nx < w:
            xor_at(field, ny, nx)

def use_dp(field): #=> flip, destructive
    h, w = get_size(field)
    flip = empty_field(h, w)
    for y in range(h):
        for x in range(w):
            if y >= 2 and field[y-2][x]:
                flip_at(field, y, x)
                xor_at(flip, y, x)
    for y in range(h-2):
        assert not any(field[y])
    return flip

import copy
def prepare_level(field):
    field = copy.deepcopy(field)
    h, w = get_size(field)
    print('dp...', file=sys.stderr)
    flip = use_dp(field)
    field = field[ -2 : ]
    init = empty_field(2, w)
    for y in range(2):
        for x in range(w):
            print('dp...', y, x, file=sys.stderr)
            a = empty_field(h, w)
            flip_at(a, y, x)
            b = use_dp(a)
            xor_at(b, y, x)
            init[y][x] = ( a[ -2 : ], b )
    return (field, flip), init

import numpy as np
import gmpy2
def xoreqn_solve(a_f, a_y):
    f = np.copy(a_f)
    y = np.copy(a_y)
    assert isinstance(f, np.ndarray)
    assert isinstance(y, np.ndarray)
    n = a_f.shape[0]
    for i in range(n):
        for j in range(i+1,n):
            if f[j,i]:
                f[i], f[j] = np.copy(f[j]), np.copy(f[i])
                y[i], y[j] = np.copy(y[j]), np.copy(y[i])
                break
        for j in range(n):
            if j != i and f[j,i]:
                f[j] = (f[j] + f[i]) % 2
                y[j] = (y[j] + y[i]) % 2
    assert np.array_equal(a_f.dot(y) % 2, a_y)
    return y

import numpy as np
def linalg_level(a, bs):
    h, w = get_size(a[1])
    vxs = []
    for parity in range(2):
        print('construct equation...', parity, file=sys.stderr)
        vy = np.zeros(w, dtype=int)
        for y in range(2):
            for x in range(w):
                if (y + x) % 2 == parity:
                    vy[(y*w+x)//2] = a[0][y][x]
        mf = np.zeros((w, w), dtype=int)
        for y in range(2):
            for x in range(w):
                if (y + x) % 2 == parity:
                    for by in range(2):
                        for bx in range(w):
                            if bs[by][bx][0][y][x]:
                                assert (h + by + bx) % 2 == (y + x) % 2
                                mf[(y*w+x)//2, (by*w+bx)//2] = 1
        print('solve equation...', parity, file=sys.stderr)
        vx = xoreqn_solve(mf, vy)
        assert np.array_equal(mf.dot(vx) % 2, vy)
        vxs += [ vx ]
    var = [ [ vxs[(h+y+x)%2][(y*w+x)//2] for x in range(w) ] for y in range(2) ]
    return var

def reconstruct_level(a, bs, var):
    print('reconstruct...', file=sys.stderr)
    _, w = get_size(a[0])
    result = a[1]
    for y in range(2):
        for x in range(w):
            if var[y][x]:
                result = xor_field(result, bs[y][x][1])
    return result

import copy
def solve_level(field):
    h, w = get_size(field)
    a, bs = prepare_level(field)
    var = linalg_level(a, bs)
    result = reconstruct_level(a, bs, var)
    return result

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('level', choices=[ 'easy', 'normal', 'lunatic' ])
parser.add_argument('check', nargs='?', default='http://ppc1.chal.ctf.westerns.tokyo:19283/check')
args = parser.parse_args()

level = load_level(args.level)
f = encode_field(level['map'], level['height'], level['width'])
g = solve_level(f)
s = decode_field(g)
submit_solution(args.check, args.level, s)
```
