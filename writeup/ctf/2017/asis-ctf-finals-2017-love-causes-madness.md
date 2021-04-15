---
layout: post
redirect_from:
  - /writeup/ctf/2017/asis-ctf-finals-2017-love-causes-madness/
  - /blog/2017/09/11/asis-ctf-finals-2017-love-causes-madness/
date: "2017-09-11T08:09:57+09:00"
tags: [ "ctf", "writeup", "ppc", "asis-ctf", "bitcoin", "prime-factrization" ]
---

# ASIS CTF Finals 2017: Love Causes Madness

前回のそれで思い出したので異国の言葉をしたが、今回は特に難しい問題は解けてないので不要だった気がする。

## problem

```
$ nc 178.62.22.245 41662
| Hi all, let's go to play with numbers!!
| Are you ready? [Y]es or [N]o: Y
| Send a BTC valid address that starts with 1AEA2: 1AEA2zssL33y2vNq5sH5pGpaw2AJb8Yt4
| For a given number n, send the number of pairs (x, y) where 2*x < x + y < n, and gcd(x, y) * n = x * y
| ------------------------------------------------------------------------------------------------------
| n = 220262691366191198475910386319170190399434875849232940348458605581200778264183963324274397378990139675229821848504179869700787541631106397146041900212453925889924760120811998658401
| Send the number of desired pairs: 
```

## solution

`ASIS{_th1s_7Im3_Pl4iN9_WitH_LCM_!!}`

### bitcoin address part

Use an address-generator like <https://github.com/weex/addrgen>.
Make an address, replace the prefix with specified one, re-calculate the checksum.

### main problems

1.  compute prime factrization of $n$
    -   use yafu and primefac-fork on AWS
2.  count the pairs
    -   just do it using C++

## note

-   PythonでCPU boundの処理を並列化するの難しい
    -   CPython + `threading`はだめってreferenceに書いてある
    -   `multiprocessing`だと色々試してもCPU使用率が$50$%を越えなかった (物理コアは使い切ってるのでよしという意見もあるが)
    -   `pwnlib.process`や`subprocess`で無理矢理やった
-   素因数分解
    -   [msieve](https://sourceforge.net/projects/msieve/) はあまり奮わなかった
    -   [primefac-fork](https://github.com/elliptic-shiho/primefac-fork) は安定感がある
    -   [yafu](https://sites.google.com/site/bbuhrow/home) が強い
        -   <http://inaz2.hatenablog.com/entry/2016/01/14/230032>
        -   ときたま途中で諦めるので残りをprimefacする必要があった
        -   並列化は `$ yafu 'factor(123456789)' -threads 32`
        -   helpは`./docfile.txt`を読みにいく
    -   ECMなどは乱択なので並列化が効くらしい

## implementation

### a.py

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='178.62.22.245')
parser.add_argument('port', nargs='?', default=41662, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--num-threads', default=4, type=int)
args = parser.parse_args()
context.log_level = args.log_level
p = remote(args.host, args.port)

# | Hi all, let's go to play with numbers!!
p.sendlineafter('| Are you ready? [Y]es or [N]o: ', 'Y')

import addrgen  # https://github.com/weex/addrgen
import random
p.recvuntil('| Send a BTC valid address that starts with ')
prefix = p.recvuntil(': ', drop=True)
log.info('prefix = %s', prefix)
addr, _ = addrgen.get_addr(addrgen.gen_eckey())
addr = prefix + addr[len(prefix) :]
k = addrgen.base58_decode_padded(addr)
v0, data, _ = k[0], k[1 : -4], k[-4 :]
addr = addrgen.base58_check_encode(data, version=ord(v0))
p.sendline(addr)

import sys
import time
class TimeoutError(Exception):
    pass
class ExitStack(object):
    def __init__(self):
        self.stack = []
    def __enter__(self):
        return self
    def enter_context(self, ctxt):
        self.stack += [ ctxt ]
        return ctxt.__enter__()
    def __exit__(self, exc_type, exc_value, traceback):
        while self.stack:
            ctxt = self.stack.pop()
            ctxt.__exit__(exc_type, exc_value, traceback)
def parallel_primefac_ecm(n, num_workers=args.num_threads):
    begin = time.time()
    with ExitStack() as stack:
        procs = []
        procs += [ stack.enter_context( process([ './b.py', '1', str(n) ], stderr=sys.stderr) ) ]
        for _ in range(num_workers - 1):
            procs += [ stack.enter_context( process([ './b.py', '2', str(n) ], stderr=sys.stderr) ) ]
        while True:
            for proc in procs:
                if proc.can_recv():
                    try:
                        len_result = int(proc.recvline())
                    except EOFError:
                        len_result = 0
                    result = []
                    for _ in range(len_result):
                        result += [ int(proc.recvline()) ]
                    if result:
                        return result
                    else:
                        procs.remove(proc)
            if time.time() - begin >= 30:
                raise TimeoutError()
            time.sleep(0.1)

import sys
import re
import subprocess
def primefac_yafu(n, num_workers=args.num_threads):
    proc = subprocess.Popen([ 'yafu', 'factor(%d)' % n, '-threads', str(num_workers), '-v' ], stdout=subprocess.PIPE, stderr=sys.stderr)
    output, _ = proc.communicate()
    for line in output.splitlines():
        if re.match(r'^P\d+ = \d+$', line):
            p = int(line.split()[2])
            assert n % p == 0
            n //= p
            yield p
    # assert n == 1
    if n != 1:
        log.info('yafu failed: %d', n)
        for p in parallel_primefac_ecm(n, num_workers=num_workers):
            yield p

class TimeLogger(object):
    def __enter__(self):
        self.begin = time.time()
    def __exit__(self, exc_type, exc_value, traceback):
        log.info('%2.f sec elapsed', time.time() - self.begin)

import gmpy2
import collections
# | For a given number n, send the number of pairs (x, y) where 2*x < x + y < n, and gcd(x, y) * n = x * y
# | ------------------------------------------------------------------------------------------------------
for _ in range(100):
    p.recvuntil('| n = ')
    n = int(p.recvline())
    log.info('n = %d', n)
    with TimeLogger() as timer:
        prime_factors = sorted(primefac_yafu(n, num_workers=args.num_threads))
        log.info('prime factors = %s', str(list(map(int, prime_factors))))
    with TimeLogger() as timer:
        with process([ './a.out' ], stderr=sys.stderr, env={ 'OMP_NUM_THREADS': str(args.num_threads) }) as proc:
            proc.sendline(str(len(prime_factors)))
            for prime_factor in prime_factors:
                proc.sendline(str(prime_factor))
            answer = int(proc.recvline())
        log.info('answer = %d', answer)
    p.sendlineafter('| Send the number of desired pairs: ', str(answer))

p.interactive()
```


### b.py

``` python
#!/usr/bin/env python3
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('type', type=int)
parser.add_argument('n', type=int)
args = parser.parse_args()

import primefac
import _primefac
import functools
import operator
if args.type == 1:
    primes = list(primefac.factorint(args.n, methods=(_primefac.mpqs, _primefac.fermat, _primefac.factordb)))
elif args.type == 2:
    primes = list(primefac.factorint(args.n, trial_limit=0, methods=(_primefac.pollardRho_brent, _primefac.pollard_pm1, _primefac.williams_pp1, _primefac.ecm)))
import sys
print(primes, file=sys.stderr)

result = []
n = args.n
for p in sorted(primes):
    while n % p == 0:
        n //= p
        result += [ p ]
if functools.reduce(operator.mul, result) != args.n:
    result = []
print(len(result))
print(*result, sep='\n')
```

### a.cpp

`clang++ -std=c++14 -Wall -O2 -lgmp -fopenmp a.cpp`

``` c++
#include <iostream>
#include <map>
#include <tuple>
#include <vector>
#include <boost/multiprecision/gmp.hpp>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

typedef boost::multiprecision::mpz_int integer;
int main() {
    int prime_factors_size; cin >> prime_factors_size;
    vector<integer> prime_factors(prime_factors_size);
    integer n = 1;
    repeat (i, prime_factors_size) {
        cin >> prime_factors[i];
        n *= prime_factors[i];
    }
    map<integer, pair<int, integer> > cnt;
    for (integer const & p : prime_factors) {
        auto & it = cnt[p];
        if (not it.second) {
            it.second = 1;
        }
        it.first += 1;
        it.second *= p;
    }
    vector<integer> factors;
    factors.emplace_back(1);
    for (auto && it : cnt) {
        integer const & q = it.first;
        int k = it.second.first;
        for (int i = factors.size() - 1; i >= 0; -- i) {
            integer x = factors[i];
            repeat (i, k) {
                x *= q;
                factors.push_back(x);
            }
        }
    }
    ll result = 0;
#pragma omp parallel for reduction(+:result)
    repeat (factor_index, factors.size()) {
        integer const & x = factors[factor_index];
        integer nx = n - x;
        integer y_base = 1;
        vector<pair<integer, int> > y_opt;
        for (auto && it : cnt) {
            integer const & q = it.first;
            int k = it.second.first;
            integer const & qk = it.second.second;
            if (x % qk == 0) {
                y_opt.emplace_back(q, k);
            } else {
                y_base *= qk;
            }
        }
        if (y_base >= nx) continue;
        vector<integer> ys;
        result += bool(x < y_base);
        ys.push_back(y_base);
        for (auto && it : y_opt) {
            integer const & q = it.first;
            int k = it.second;
            for (int i = ys.size() - 1; i >= 0; -- i) {
                integer y = ys[i];
                repeat (j, k) {
                    y *= q;
                    if (y >= nx) break;
                    result += bool(x < y);
                    ys.push_back(y);
                }
            }
        }
    }
    cout << result << endl;
    return 0;
}
```
