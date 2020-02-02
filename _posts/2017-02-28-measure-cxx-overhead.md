---
category: blog
layout: post
date: "2017-02-28T01:30:24+09:00"
title: "std::vector等のC++の機能の利用による速度低下について計測した"
tags: [ "competitive", "optimization" ]
---

## 概要

生配列と`std::vector`、生の`for`-loopと`boost::irange`といった間での、実行速度の差について気になったので実験した。
主な結論としては、g++では(pointerも避けて)生配列を使わないと遅い、clangだと`std::vector`だろうとちゃんと最適化される、であった。

## 設定

以下のような問題を考える。これに対する愚直$O(NQ)$実装に対し、諸々の条件を変えながら実行速度を計測する。

>   始めに長さ$N$の数列$A = (a\_0, a\_1, \dots, a\_{N-1})$が与えられる。
>   続いて$Q$個の区間$[l\_0, r\_0), [l\_1, r\_1), \dots, [l\_{Q-1}, r\_{Q-1})$が与えられるので、それぞれの区間$[l\_j, r\_j)$に対し$\max \\{ a\_i \mid l\_j \le i \lt r\_j \\}$を答えよ。

ただし制約は以下のようにする。

-   $N = 5 \times 10^5$
-   $1 \le a_i \le 10^9$
-   $Q = 10^5$
-   $0 \le l_j \lt r_j \le N$

$a_i, l_j, r_j$はそれぞれ一様な乱数として生成する。
特に以下のようにして生成したものであり、計測において全て同じ入力を用いた。

``` python
#!/usr/bin/env python3
import random
n = 5*10**5
print(n)
print(*[ random.randint(1, 10**9) for _ in range(n) ])
q = 10**5
print(q)
for _ in range(q):
    l = random.randint(0, n-1)
    r = random.randint(l+1, n)
    print(l, r)
```

基本となる実装は次である。
主に、内側のloopがloop-unrollingやSIMDによる最適化を受けるかどうかを見ることを意図しての設定である。

``` c++
#include <cstdio>
#include <algorithm>
using namespace std;
constexpr int N_MAX = 500000;
int a[N_MAX];
int main() {
    int n; scanf("%d", &n);
    for (int i = 0; i < n; ++ i) scanf("%d", &a[i]);
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        int acc = 0;
        for (int i = l; i < r; ++ i) {
            acc = max(acc, a[i]);
        }
        printf("%d\n", acc);
    }
    return 0;
}
```

これを以下のように改変したそれぞれについて計測した。

-   arrayを使う (そのまま)
-   `std::array`を使う
-   `std::vector`を使う
-   `malloc`してpointerを使う
-   `std::unique_ptr`を使う
-   loopに`boost::irange`を使う
-   `std++vector`でloopにiteratorを使う
-   `std++vector`で`std::max_element`を使う
-   `std++vector`で`std::accumulate`を使う

コンパイラ/オプションは以下のそれぞれを試した。

-   `g++ -std=c++14 -O2`
-   `g++ -std=c++14 -O3 -mtune=native -march=native`
-   `clang++ -std=c++14 -O2`
-   `clang++ -std=c++14 -O3 -mtune=native -march=native`

## 結果

上記のような設定のもと、下記環境では以下のような結果になった。

*                  | `g++ -O2 ...` | `g++ -O3 ...` | `clang++ -O2 ...` | `clang++ -O3 ...`
-------------------|---------------|---------------|-------------------|---------------------
array              |         9.20s |         1.22s |             3.20s |             1.19s
`std::array`       |         9.24s |         1.26s |             3.18s |             1.19s
`std::vector`      |         9.16s |         9.19s |             3.20s |             1.16s
pointer            |         9.16s |         9.25s |             3.19s |             1.17s
`std::unique_ptr`  |         9.19s |         9.24s |             3.19s |             1.23s
`boost::irage`     |         9.20s |         1.22s |             3.22s |             1.18s
iterator           |         9.17s |         9.19s |             3.22s |             1.18s
`std::max_element` |         9.19s |         9.18s |             7.53s |             7.52s
`std::accumulate`  |         9.20s |         9.18s |             3.20s |             1.23s

まとめると以下のようになる。

-   g++では配列 (`std::array`を含む) 以外は遅い
-   g++でも`boost::irage`は速度低下しない
-   `std::max_element`はclangでも遅い (indexまで求めているので仕方がない)
-   それ以外では、どれも生配列や生の`for`との速度差はない

また今回は問題の形状により表に乗らなかったが、g++でもrange-based for (`for (int a_i : a) { ... }`の形) + `-O3`は生配列と同程度の速度が出ていた。

## disas

生配列 + `clang -O3 ...`のとき、最も内のloopは以下のようになっていた。
loop unrollingし、avx2による`vpmaxsd`命令を`ymm0`と`ymm1`を交互に使っているようだ。

``` asm
       .--> 0x00400780      c4e27d3d8720.  vpmaxsd ymm0, ymm0, ymmword [rdi - 0xe0]
       |    0x00400789      c4e2753d8f40.  vpmaxsd ymm1, ymm1, ymmword [rdi - 0xc0]
       |    0x00400792      c4e27d3d8760.  vpmaxsd ymm0, ymm0, ymmword [rdi - 0xa0]
       |    0x0040079b      c4e2753d4f80   vpmaxsd ymm1, ymm1, ymmword [rdi - 0x80]
       |    0x004007a1      c4e27d3d47a0   vpmaxsd ymm0, ymm0, ymmword [rdi - 0x60]
       |    0x004007a7      c4e2753d4fc0   vpmaxsd ymm1, ymm1, ymmword [rdi - 0x40]
       |    0x004007ad      c4e27d3d47e0   vpmaxsd ymm0, ymm0, ymmword [rdi - 0x20]
       |    0x004007b3      c4e2753d0f     vpmaxsd ymm1, ymm1, ymmword [rdi]
       |    0x004007b8      4881c7000100.  add rdi, 0x100
       |    0x004007bf      4883c6c0       add rsi, -0x40
       `==< 0x004007c3      75bb           jne 0x400780
```

## おまけ

*            | `clang++ -std=c++14 -g -fsanitize=undefined -D_GLIBCXX_DEBUG` | `clang++ -O3 ...`
-------------|---------------------------------------------------------------|--------------------
array        |                                                       134.97s |            1.22s
sparse table |                                                         0.41s |            0.13s

## 環境

計測した環境は以下のようなものであった。

``` sh
$ cat /proc/cpuinfo
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 78
model name	: Intel(R) Core(TM) i5-6200U CPU @ 2.30GHz
stepping	: 3
microcode	: 0x8a
cpu MHz		: 427.687
cache size	: 3072 KB
physical id	: 0
siblings	: 4
core id		: 0
cpu cores	: 2
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 22
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc aperfmperf eagerfpu pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch epb intel_pt tpr_shadow vnmi flexpriority ept vpid fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt xsaveopt xsavec xgetbv1 dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp
bugs		:
bogomips	: 4799.56
clflush size	: 64
cache_alignment	: 64
address sizes	: 39 bits physical, 48 bits virtual
power management:

processor	: 1
...

processor	: 2
...

processor	: 3
...

$ g++ --version
g++ (Ubuntu 5.4.1-2ubuntu1~16.04) 5.4.1 20160904
Copyright (C) 2015 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

$ clang++ --version
clang version 3.8.0-2ubuntu4 (tags/RELEASE_380/final)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin

$ grep '#define BOOST_LIB_VERSION' /usr/include/boost/version.hpp
#define BOOST_LIB_VERSION "1_58"

$ which time
time: aliased to command time -f "%es %MKB"
```

<!-- more -->

## ログ

### 生配列

``` sh
$ cat a.cpp
#include <cstdio>
#include <algorithm>
using namespace std;
constexpr int N_MAX = 500000;
int a[N_MAX];
int main() {
    int n; scanf("%d", &n);
    for (int i = 0; i < n; ++ i) scanf("%d", &a[i]);
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        int acc = 0;
        for (int i = l; i < r; ++ i) {
            acc = max(acc, a[i]);
        }
        printf("%d\n", acc);
    }
    return 0;
}
$ g++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.21s 3416KB
9.44s 3508KB
9.17s 3464KB
9.18s 3472KB
9.14s 3468KB
9.22s 3464KB
9.16s 3460KB
9.17s 3460KB
9.17s 3436KB
9.17s 3460KB
$ g++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
1.26s 3504KB
1.24s 3472KB
1.21s 3320KB
1.20s 3472KB
1.20s 3456KB
1.21s 3428KB
1.23s 3464KB
1.18s 3328KB
1.22s 3464KB
1.22s 3460KB
$ clang++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
3.20s 4636KB
3.21s 4632KB
3.20s 4744KB
3.22s 4604KB
3.19s 4628KB
3.16s 4640KB
3.20s 4636KB
3.22s 4640KB
3.22s 4672KB
3.16s 4676KB
$ clang++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
1.13s 4636KB
1.22s 4636KB
1.15s 4564KB
1.18s 4668KB
1.21s 4744KB
1.20s 4588KB
1.19s 4744KB
1.21s 4576KB
1.18s 4656KB
1.18s 4744KB
$ clang++ -std=c++14 -g -fsanitize=undefined -D_GLIBCXX_DEBUG a.cpp
$ time ./a.out < input > /dev/null
134.97s 8204KB
```

### std::array

``` sh
$ cat a.cpp
#include <cstdio>
#include <algorithm>
#include <array>
using namespace std;
constexpr int N_MAX = 500000;
array<int,N_MAX> a;
int main() {
    int n; scanf("%d", &n);
    for (int i = 0; i < n; ++ i) scanf("%d", &a[i]);
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        int acc = 0;
        for (int i = l; i < r; ++ i) {
            acc = max(acc, a[i]);
        }
        printf("%d\n", acc);
    }
    return 0;
}
$ g++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.33s 3460KB
9.17s 3432KB
9.16s 3444KB
9.15s 3448KB
9.36s 3468KB
9.17s 3456KB
9.20s 3448KB
9.19s 3468KB
9.26s 3468KB
9.37s 3420KB
$ g++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
1.25s 3424KB
1.23s 3468KB
1.17s 3468KB
1.24s 3464KB
1.27s 3444KB
1.66s 3464KB
1.22s 3468KB
1.19s 3500KB
1.16s 3432KB
1.24s 3432KB
$ clang++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
3.17s 4668KB
3.21s 4632KB
3.17s 4640KB
3.15s 4668KB
3.17s 4628KB
3.19s 4652KB
3.18s 4628KB
3.18s 4668KB
3.18s 4636KB
3.19s 4740KB
$ clang++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
1.21s 4604KB
1.14s 4552KB
1.23s 4744KB
1.14s 4640KB
1.20s 4632KB
1.15s 4584KB
1.21s 4600KB
1.19s 4628KB
1.19s 4628KB
1.19s 4584KB
```

### std::vector

``` sh
$ cat a.cpp
#include <cstdio>
#include <algorithm>
#include <vector>
using namespace std;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); for (int i = 0; i < n; ++ i) scanf("%d", &a[i]);
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        int acc = 0;
        for (int i = l; i < r; ++ i) {
            acc = max(acc, a[i]);
        }
        printf("%d\n", acc);
    }
    return 0;
}
$ g++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.14s 4068KB
9.12s 4172KB
9.20s 4152KB
9.17s 4184KB
9.18s 4152KB
9.22s 4188KB
9.13s 4056KB
9.14s 4192KB
9.19s 4280KB
9.15s 4140KB
$ g++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.23s 4168KB
9.18s 4160KB
9.15s 4192KB
9.19s 4148KB
9.19s 4152KB
9.16s 4192KB
9.20s 4184KB
9.16s 4152KB
9.22s 4184KB
9.21s 4192KB
$ clang++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
3.23s 4124KB
3.21s 4256KB
3.17s 4136KB
3.15s 4120KB
3.23s 4160KB
3.18s 4156KB
3.17s 4256KB
3.18s 4136KB
3.21s 4120KB
3.25s 4120KB
$ clang++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
1.16s 4256KB
1.19s 4136KB
1.13s 4144KB
1.16s 4132KB
1.17s 4136KB
1.15s 4160KB
1.19s 4256KB
1.12s 4108KB
1.16s 4144KB
1.12s 4224KB
```

### pointer

``` sh
$ cat a.cpp
#include <cstdio>
#include <algorithm>
#include <cstdlib>
using namespace std;
int main() {
    int n; scanf("%d", &n);
    int *a = static_cast<int *>(malloc(n * sizeof(int)));
    for (int i = 0; i < n; ++ i) scanf("%d", &a[i]);
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        int acc = 0;
        for (int i = l; i < r; ++ i) {
            acc = max(acc, a[i]);
        }
        printf("%d\n", acc);
    }
    return 0;
}
$ g++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.15s 3448KB
9.20s 3440KB
9.15s 3464KB
9.16s 3464KB
9.17s 3472KB
9.19s 3452KB
9.13s 3508KB
9.13s 3472KB
9.19s 3468KB
9.14s 3448KB
$ g++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.19s 3448KB
9.27s 3436KB
9.24s 3476KB
9.22s 3480KB
9.23s 3432KB
9.28s 3436KB
9.31s 3476KB
9.28s 3476KB
9.25s 3420KB
9.26s 3452KB
$ clang++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
3.21s 4644KB
3.18s 4632KB
3.22s 4632KB
3.15s 4640KB
3.18s 4552KB
3.18s 4640KB
3.22s 4644KB
3.24s 4556KB
3.18s 4592KB
3.18s 4684KB
$ clang++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
1.20s 4656KB
1.16s 4584KB
1.16s 4604KB
1.15s 4644KB
1.18s 4668KB
1.18s 4560KB
1.16s 4632KB
1.15s 4684KB
1.22s 4628KB
1.16s 4640KB
```

### `std::unique_ptr`

``` sh
$ cat a.cpp
#include <cstdio>
#include <algorithm>
#include <memory>
using namespace std;
int main() {
    int n; scanf("%d", &n);
    unique_ptr<int[]> a = make_unique<int[]>(n);
    for (int i = 0; i < n; ++ i) scanf("%d", &a[i]);
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        int acc = 0;
        for (int i = l; i < r; ++ i) {
            acc = max(acc, a[i]);
        }
        printf("%d\n", acc);
    }
    return 0;
}
$ g++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.26s 4056KB
9.22s 4160KB
9.21s 4160KB
9.22s 4104KB
9.21s 4068KB
9.15s 4184KB
9.21s 4184KB
9.12s 4096KB
9.17s 4172KB
9.11s 4200KB
$ g++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.28s 4152KB
9.44s 4188KB
9.25s 4136KB
9.17s 4152KB
9.24s 4140KB
9.21s 4184KB
9.23s 4280KB
9.19s 4152KB
9.22s 4200KB
9.19s 4196KB
$ clang++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
3.20s 4256KB
3.17s 4136KB
3.15s 4176KB
3.20s 4172KB
3.19s 4172KB
3.24s 4216KB
3.20s 4220KB
3.15s 4128KB
3.20s 4204KB
3.20s 4128KB
$ clang++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
1.19s 4136KB
1.23s 4136KB
1.25s 4100KB
1.23s 4220KB
1.23s 4172KB
1.23s 4128KB
1.29s 4172KB
1.20s 4176KB
1.19s 4152KB
1.23s 4172KB
```

### boost::irange

``` sh
$ cat a.cpp
#include <cstdio>
#include <algorithm>
#include <boost/range/irange.hpp>
using namespace std;
constexpr int N_MAX = 500000;
int a[N_MAX];
int main() {
    int n; scanf("%d", &n);
    for (int i = 0; i < n; ++ i) scanf("%d", &a[i]);
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        int acc = 0;
        for (int i : boost::irange(l, r)) {
            acc = max(acc, a[i]);
        }
        printf("%d\n", acc);
    }
    return 0;
}
$ g++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.22s 3464KB
9.15s 3504KB
9.20s 3464KB
9.22s 3468KB
9.22s 3456KB
9.21s 3460KB
9.21s 3420KB
9.15s 3416KB
9.20s 3428KB
9.26s 3432KB
$ g++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
1.20s 3464KB
1.16s 3424KB
1.18s 3460KB
1.18s 3464KB
1.22s 3424KB
1.23s 3464KB
1.28s 3432KB
1.25s 3472KB
1.21s 3436KB
1.28s 3428KB
$ clang++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
3.22s 4640KB
3.28s 4640KB
3.16s 4600KB
3.21s 4636KB
3.25s 4744KB
3.17s 4632KB
3.25s 4680KB
3.23s 4604KB
3.22s 4604KB
3.19s 4584KB
$ clang++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
1.28s 4600KB
1.27s 4588KB
1.17s 4552KB
1.17s 4680KB
1.16s 4664KB
1.14s 4580KB
1.19s 4668KB
1.16s 4636KB
1.13s 4584KB
1.15s 4668KB
```

### iterator

``` sh
$ cat a.cpp
#include <cstdio>
#include <algorithm>
#include <vector>
using namespace std;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); for (int i = 0; i < n; ++ i) scanf("%d", &a[i]);
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        int acc = 0;
        for (auto it = a.begin() + l; it != a.begin() + r; ++ it) {
            acc = max(acc, *it);
        }
        printf("%d\n", acc);
    }
    return 0;
}
$ g++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.17s 4136KB
9.13s 4068KB
9.20s 4160KB
9.17s 4168KB
9.19s 4068KB
9.13s 4172KB
9.21s 4160KB
9.16s 4080KB
9.20s 4184KB
9.18s 4176KB
$ g++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.19s 4156KB
9.17s 4176KB
9.18s 4160KB
9.22s 4184KB
9.22s 4192KB
9.17s 4136KB
9.21s 4128KB
9.14s 4128KB
9.19s 4160KB
9.20s 4140KB
$ clang++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
3.22s 4220KB
3.24s 4188KB
3.21s 4256KB
3.24s 4144KB
3.18s 4120KB
3.19s 4180KB
3.19s 4220KB
3.25s 4220KB
3.25s 4120KB
3.23s 4176KB
$ clang++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
1.22s 4160KB
1.19s 4180KB
1.13s 4144KB
1.22s 4220KB
1.20s 4136KB
1.17s 4172KB
1.19s 4256KB
1.13s 4256KB
1.12s 4256KB
1.21s 4104KB
```

### `std::max_element`

``` sh
$ cat a.cpp
#include <cstdio>
#include <algorithm>
#include <vector>
using namespace std;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); for (int i = 0; i < n; ++ i) scanf("%d", &a[i]);
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        int acc = *max_element(a.begin() + l, a.begin() + r);
        printf("%d\n", acc);
    }
    return 0;
}
$ g++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.17s 4052KB
9.15s 4064KB
9.21s 4096KB
9.18s 4176KB
9.24s 4160KB
9.22s 4204KB
9.22s 4192KB
9.18s 4284KB
9.15s 4284KB
9.14s 4200KB
$ g++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.27s 4140KB
9.22s 4192KB
9.16s 4112KB
9.15s 4192KB
9.19s 4284KB
9.16s 4156KB
9.21s 4128KB
9.12s 4164KB
9.17s 4200KB
9.12s 4172KB
$ clang++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
7.65s 4216KB
7.52s 4172KB
7.50s 4136KB
7.52s 4160KB
7.51s 4136KB
7.50s 4176KB
7.50s 4188KB
7.50s 4104KB
7.57s 4116KB
7.52s 4172KB
$ clang++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
7.58s 4220KB
7.54s 4140KB
7.54s 4188KB
7.55s 4136KB
7.52s 4180KB
7.56s 4136KB
7.49s 4120KB
7.48s 4172KB
7.50s 4144KB
7.46s 4132KB
```

### `std::accumulate`

``` sh
$ cat a.cpp
#include <cstdio>
#include <numeric>
#include <vector>
using namespace std;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); for (int i = 0; i < n; ++ i) scanf("%d", &a[i]);
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        int acc = accumulate(a.begin() + l, a.begin() + r, 0, max<int>);
        printf("%d\n", acc);
    }
    return 0;
}
$ g++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.25s 4140KB
9.16s 4080KB
9.21s 4152KB
9.17s 4284KB
9.22s 4140KB
9.16s 4056KB
9.24s 4184KB
9.16s 4172KB
9.17s 4172KB
9.25s 4192KB
$ g++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
9.19s 4160KB
9.16s 4136KB
9.17s 4140KB
9.13s 4152KB
9.24s 4152KB
9.14s 4140KB
9.24s 4128KB
9.14s 4192KB
9.22s 4184KB
9.18s 4128KB
$ clang++ -std=c++14 -O2 a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
3.21s 4220KB
3.18s 4208KB
3.16s 4140KB
3.15s 4120KB
3.21s 4172KB
3.22s 4188KB
3.24s 4136KB
3.19s 4208KB
3.23s 4160KB
3.24s 4220KB
$ clang++ -std=c++14 -O3 -mtune=native -march=native a.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
1.26s 4172KB
1.16s 4104KB
1.18s 4128KB
1.23s 4188KB
1.23s 4180KB
1.34s 4180KB
1.25s 4180KB
1.22s 4188KB
1.19s 4220KB
1.27s 4172KB
```

### sparse table

``` sh
$ cat b.cpp
#include <cstdio>
#include <algorithm>
#include <cmath>
using namespace std;
constexpr int MAX_N = 500000;
constexpr int LOG_N = 19;
int table[LOG_N][MAX_N];
int main() {
    int n; scanf("%d", &n);
    for (int i = 0; i < n; ++ i) scanf("%d", &table[0][i]);
    for (int k = 0; k < LOG_N-1; ++ k) {
        for (int i = 0; i < n; ++ i) {
            table[k+1][i] = max(table[k][i], i + (1<<k) < n ? table[k][i + (1<<k)] : 0);
        }
    }
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        int k = log2(r - l);
        int acc = max(table[k][l], table[k][r - (1<<k)]);
        printf("%d\n", acc);
    }
    return 0;
}
$ clang++ -std=c++14 -g -fsanitize=undefined -D_GLIBCXX_DEBUG b.cpp
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
0.41s 43484KB
0.41s 43468KB
0.40s 43520KB
0.40s 43472KB
0.42s 43468KB
0.41s 43472KB
0.41s 43472KB
0.41s 43464KB
0.41s 43616KB
0.41s 43624KB
$ for i in `seq 10` ; do time ./a.out < input > /dev/null ; done
0.14s 39984KB
0.13s 40092KB
0.14s 39984KB
0.13s 39912KB
0.13s 39952KB
0.13s 39976KB
0.13s 40096KB
0.13s 39924KB
0.14s 40016KB
0.13s 40096KB
```

---

-   2017年  2月 28日 火曜日 22:40:43 JST
    -   計測すべき対象をいくつか忘れていたので追加
-   2017年  3月  1日 水曜日 20:11:35 JST
    -   disassembleして確認してなかったので追加
