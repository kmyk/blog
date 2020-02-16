---
category: blog
layout: post
date: "2017-06-07T16:53:26+09:00"
edited: "2018-12-14T00:00:00+09:00"
tags: [ "c++", "bitset", "optimization" ]
---

# std::bitset<N> や std::vector<bool> の速度について

雑な測定なので参考程度にどうぞ。

## まとめ

-   `bitset<N>`は速い
    -   速さは$2$倍だったり$500$倍だったりする
-   `vector<bool>`は遅め
    -   `vector<char>`での置き換えはあり
    -   ただし`deque<bool>`だともっと遅くなる
-   `array<bool, N>`はそうでもない
    -   コンパイラは賢いので`vector<char>`が同じぐらいになる

## 測定内容

以下のクラスのそれぞれについて、

-   `bitset<N>`
-   `vector<bool>`
-   `vector<char>`
-   `deque<bool>`
-   `deque<char>`
-   `array<bool, N>`
-   `array<char, N>`

次の処理をそれぞれ実行させて計測した。

-   xor
-   or
-   shuffle
-   shift

## 表

### 操作: `xor`

| type             | N         | iteration    | elapsed           | ratio   |
|------------------|-----------|--------------|-------------------|---------|
| `bitset<N>`      | $1000000$ | $1000      $ | $9              $ |  -      |
| `bitset<N>`      | $1000000$ | $1000000   $ | $9708           $ | $1    $ |
| `vector<bool>`   | $1000000$ | $1000      $ | $2218           $ | $228  $ |
| `vector<char>`   | $1000000$ | $1000      $ | $744            $ | $76.6 $ |
| `deque<bool>`    | $1000000$ | $1000      $ | $3674           $ | $378  $ |
| `deque<char>`    | $1000000$ | $1000      $ | $4721           $ | $486  $ |
| `array<bool, N>` | $1000000$ | $1000      $ | $621            $ | $65.1 $ |
| `array<char, N>` | $1000000$ | $1000      $ | $726            $ | $74.8 $ |

経過時間の単位はミリ秒。
比は `bitset<N>` から何倍遅いかを表す。

### 操作: `or`

| type             | N         | iteration    | elapsed           | ratio   |
|------------------|-----------|--------------|-------------------|---------|
| `bitset<N>`      | $1000000$ | $1000      $ | $9              $ |  -      |
| `bitset<N>`      | $1000000$ | $1000000   $ | $10117          $ | $1    $ |
| `vector<bool>`   | $1000000$ | $1000      $ | $1919           $ | $190  $ |
| `vector<char>`   | $1000000$ | $1000      $ | $5194           $ | $513  $ |
| `deque<bool>`    | $1000000$ | $1000      $ | $11144          $ | $1102 $ |
| `deque<char>`    | $1000000$ | $1000      $ | $10209          $ | $1009 $ |
| `array<bool, N>` | $1000000$ | $1000      $ | $5394           $ | $533  $ |
| `array<char, N>` | $1000000$ | $1000      $ | $5373           $ | $531  $ |

### 操作: `shuffle`

| type             | N         | iteration    | elapsed           | ratio   |
|------------------|-----------|--------------|-------------------|---------|
| `bitset<N>`      | $1000000$ | $1000      $ | $6890           $ | $1    $ |
| `vector<bool>`   | $1000000$ | $1000      $ | $6864           $ | $0.996$ |
| `vector<char>`   | $1000000$ | $1000      $ | $4792           $ | $0.696$ |
| `deque<bool>`    | $1000000$ | $1000      $ | $5014           $ | $0.728$ |
| `deque<char>`    | $1000000$ | $1000      $ | $5154           $ | $0.748$ |
| `array<bool, N>` | $1000000$ | $1000      $ | $4719           $ | $0.685$ |
| `array<char, N>` | $1000000$ | $1000      $ | $4801           $ | $0.697$ |

### 操作: `shift`

| type             | N         | iteration    | elapsed           | ratio   |
|------------------|-----------|--------------|-------------------|---------|
| `bitset<N>`      | $1000000$ | $1000      $ | $20             $ |  -      |
| `bitset<N>`      | $1000000$ | $1000000   $ | $2098           $ | $1    $ |
| `vector<bool>`   | $1000000$ | $1000      $ | $6237           $ | $2973 $ |
| `vector<char>`   | $1000000$ | $1000      $ | $54             $ |  -      |
| `vector<char>`   | $1000000$ | $1000      $ |  -                |  -      |
| `deque<bool>`    | $1000000$ | $1000      $ | $2924           $ | $1394 $ |
| `deque<char>`    | $1000000$ | $1000      $ | $4065           $ | $1938 $ |
| `array<bool, N>` | $1000000$ | $1000      $ | $48             $ |  -      |
| `array<bool, N>` | $1000000$ | $1000000   $ | $4686           $ | $2.23 $ |
| `array<char, N>` | $1000000$ | $1000      $ | $49             $ |  -      |
| `array<char, N>` | $1000000$ | $1000      $ |  -                |  -      |

## 結果と考察

(ランダムアクセスを除いて) `bitset`は速い。
例えばshiftを取るときの`array<bool, N>`と比べると$\frac{4686}{100000} / \frac{2098}{100000} \approx 2.234$倍速く、
orを取るときの`bitset<N>`は、`vector<char>`に比べて$\frac{5194}{1000} / \frac{10117}{1000000} \approx 513.4$倍速い。
実際に吐かれた機械語を見るとAVX2命令が出現している。

`bitset`のランダムアクセスは遅い。
これは`std::bitset::operator []`は(特に参照が必要なときは)`std::bitset::reference`というwrapper構造体を返すためだろう。
つまり`vector<bool>`のそれとまったく同じ理由で遅い。
なお空間効率が$8$倍良いのでcacheには乗りやすいだろうが、それを狙うのならば`vector<bool>`を使っても同じである。

`vector<bool>`は遅い。
速度の点で`vector<char>`にするのは有効といってよさそう。
といっても致命的に遅いということはなく`deque<bool>`などよりはむしろ速い。

`vector<char>`は速いが遅い場合もある。
文字列操作系の命令に落ちることができるも速度に影響しているはずである (未確認)。
空間効率の点では`vector<bool>`に劣るので、常に速いというのは偽である。

`deque<bool>`, `deque<char>`は遅い。
コンパイラによる最適化が難しいのでその点が嬉しくない。
これらを使う理由が速度がならば代わりに`vector<bool>`を使うべきだろう。

`array<bool, N>`は奮わなかった。
今回はどれも`vector<char>`と等速であった。
`bitset`と同じようにAVX2命令が使われて$\frac{1}{8}$ぐらいの速度が出ると予想されたがそうではなく、またコンパイラが`vector`の中身が何か見抜けたため差が消えてしまったようだ。
しかし古いGCC (例えば `g++ (Ubuntu 5.4.1-2ubuntu1~16.04) 5.4.1 20160904`)などであると、`vector`を配列と同じようには最適化してくれないことが知られているので注意すること。
新しいコンパイラであっても、例えばshuffleとshiftの場合ではコンパイラが処理を丸ごと消去する(ので修正のうえ比較している)など、速度がどうしても必要であればこちらを使っておくべきだろう。

## 実装

``` c++
#include <iostream>
#include <cstdlib>
#include <random>
#include <chrono>
#include <vector>
#include <deque>
#include <bitset>
#include <array>
using namespace std;

default_random_engine gen; // fixed seed

template <class T>
void initialize(T & xs) {
    xs.resize(N);
    for (int i = 0; i < N; ++ i) {
        xs[i] = bernoulli_distribution(0.5)(gen);
    }
}
template <>
void initialize(bitset<N> & xs) {
    for (int i = 0; i < N; ++ i) {
        xs[i] = bernoulli_distribution(0.5)(gen);
    }
}
template <>
void initialize(array<bool, N> & xs) {
    for (int i = 0; i < N; ++ i) {
        xs[i] = bernoulli_distribution(0.5)(gen);
    }
}
template <>
void initialize(array<char, N> & xs) {
    for (int i = 0; i < N; ++ i) {
        xs[i] = bernoulli_distribution(0.5)(gen);
    }
}

void flush_cache(int size = 32 * 1024 * 1024) {
    volatile char *s = (char *)malloc(size);
    for (int i = 0; i < size; ++ i) {
        s[i] = 'A';
    }
    free((void *)s);
}

template <class T>
void func_xor(T & a, T & b) {
    for (int i = 0; i < N; ++ i) {
        b[i] = a[i] != b[i];
    }
}
template <>
void func_xor(bitset<N> & a, bitset<N> & b) {
    b ^= a;
}

template <class T>
void func_or(T & a, T & b) {
    for (int i = 0; i < N; ++ i) {
        b[i] = a[i] || b[i];
    }
}
template <>
void func_or(bitset<N> & a, bitset<N> & b) {
    b |= a;
}

template <class T>
void func_shuffle(T & a, T & b) {
    size_t p = uniform_int_distribution<size_t>(0, N-1)(gen);
    size_t q = uniform_int_distribution<size_t>(0, N-1)(gen);
    size_t x = 0;
    for (int i = 0; i < N; ++ i) {
        b[x] = a[i];
        x = (p * x + q) % N;
    }
}

template <class T>
void func_shift(T & a, T & b) {
    size_t k = uniform_int_distribution<size_t>(0, 1000)(gen);
    for (int i = 0; i < k; ++ i) {
        b[i] = 0;
    }
    for (int i = 0; i < N-k; ++ i) {
        b[i+k] = a[i];
    }
}
template <>
void func_shift(bitset<N> & a, bitset<N> & b) {
    size_t k = uniform_int_distribution<size_t>(0, 1000)(gen);
    b = a << k;
}

int main() {
    TYPE a; initialize(a);
    TYPE b; initialize(b);
    flush_cache();
    auto clock_begin = chrono::system_clock::now();
    for (volatile int iteration = 0; iteration < ITERATION; ++ iteration) {
        FUNC(a, b);
    }
    auto clock_end = chrono::system_clock::now();
    auto elapsed = chrono::duration_cast<chrono::milliseconds>(clock_end - clock_begin).count();
    cout << elapsed << "msec" << endl;
    return 0;
}
```

## 出力一覧

```
$ cxx -DTYPE='bitset<N>' -DFUNC=func_xor -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
9msec
$ cxx -DTYPE='bitset<N>' -DFUNC=func_xor -DN=1000000 -DITERATION=1000000 a.cpp && ./a.out
9708msec
$ cxx -DTYPE='vector<bool>' -DFUNC=func_xor -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
2218msec
$ cxx -DTYPE='vector<char>' -DFUNC=func_xor -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
744msec
$ cxx -DTYPE='deque<bool>' -DFUNC=func_xor -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
3674msec
$ cxx -DTYPE='deque<char>' -DFUNC=func_xor -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
4721msec
$ cxx -DTYPE='array<bool, N>' -DFUNC=func_xor -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
621msec
$ cxx -DTYPE='array<char, N>' -DFUNC=func_xor -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
726msec
```

```
$ cxx -DTYPE='bitset<N>' -DFUNC=func_or -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
9msec
$ cxx -DTYPE='bitset<N>' -DFUNC=func_or -DN=1000000 -DITERATION=1000000 a.cpp && ./a.out
10117msec
$ cxx -DTYPE='vector<bool>' -DFUNC=func_or -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
1919msec
$ cxx -DTYPE='vector<char>' -DFUNC=func_or -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
5194msec
$ cxx -DTYPE='deque<char>' -DFUNC=func_or -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
11144msec
$ cxx -DTYPE='deque<bool>' -DFUNC=func_or -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
10209msec
$ cxx -DTYPE='array<bool, N>' -DFUNC=func_or -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
5349msec
$ cxx -DTYPE='array<char, N>' -DFUNC=func_or -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
5373msec
```

```
$ cxx -DTYPE='bitset<N>' -DFUNC=func_shuffle -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
6890msec
$ cxx -DTYPE='vector<bool>' -DFUNC=func_shuffle -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
6864msec
$ cxx -DTYPE='vector<char>' -DFUNC=func_shuffle -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
4792msec
$ cxx -DTYPE='deque<bool>' -DFUNC=func_shuffle -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
5014msec
$ cxx -DTYPE='deque<char>' -DFUNC=func_shuffle -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
5154msec
$ cxx -DTYPE='array<bool, N>' -DFUNC=func_shuffle -DN=1000000 -DITERATION=1000 -c a.cpp && clang++ a.o && ./a.out
4719msec
$ cxx -DTYPE='array<char, N>' -DFUNC=func_shuffle -DN=1000000 -DITERATION=1000 -c a.cpp && clang++ a.o && ./a.out
4801msec
```

```
$ cxx -DTYPE='bitset<N>' -DFUNC=func_shift -DN=1000000 -DITERATION=1000 -c a.cpp && clang++ a.o && ./a.out
20msec
$ cxx -DTYPE='bitset<N>' -DFUNC=func_shift -DN=1000000 -DITERATION=100000 -c a.cpp && clang++ a.o && ./a.out
2098msec
$ cxx -DTYPE='vector<bool>' -DFUNC=func_shift -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
6237msec
$ cxx -DTYPE='vector<char>' -DFUNC=func_shift -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
54msec
$ cxx -DTYPE='deque<bool>' -DFUNC=func_shift -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
2924msec
$ cxx -DTYPE='deque<char>' -DFUNC=func_shift -DN=1000000 -DITERATION=1000 a.cpp && ./a.out
4065msec
$ cxx -DTYPE='array<bool, N>' -DFUNC=func_shift -DN=1000000 -DITERATION=1000 -c a.cpp && clang++ a.o && ./a.out
48msec
$ cxx -DTYPE='array<bool, N>' -DFUNC=func_shift -DN=1000000 -DITERATION=100000 -c a.cpp && clang++ a.o && ./a.out
4686msec
$ cxx -DTYPE='array<char, N>' -DFUNC=func_shift -DN=1000000 -DITERATION=1000 -c a.cpp && clang++ a.o && ./a.out
49msec
```

ただし

```
$ which cxx
cxx: aliased to clang++ -std=c++14 -Wall -O3 -mtune=native -march=native
```

shiftかつ`array`の場合は処理がコンパイラに丸ごと除去されたようなので対応した。他も同様にやるべきだったのだろうが、速度面で特に影響はなさそうなためこのままとする。

## 環境

```
$ clang++ --version
clang version 3.8.0-2ubuntu4 (tags/RELEASE_380/final)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```

```
$ uname -a
Linux user-ThinkPad-X260 4.4.0-78-generic #99-Ubuntu SMP Thu Apr 27 15:29:09 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```

STLはlibstdc++

```
$ md5sum /usr/lib/x86_64-linux-gnu/libstdc++.so.6
9c4080735fe3e92ae40b81ad17fbd9c5  /usr/lib/x86_64-linux-gnu/libstdc++.so.6
```

```
$ cat /proc/cpuinfo
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 78
model name	: Intel(R) Core(TM) i5-6200U CPU @ 2.30GHz
stepping	: 3
microcode	: 0x8a
cpu MHz		: 499.968
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
bogomips	: 4799.82
clflush size	: 64
cache_alignment	: 64
address sizes	: 39 bits physical, 48 bits virtual
power management:

processor	: 1
...
```

---

# std::bitset<N> や std::vector<bool> の速度について

-   2018年 12月 14日 金曜日 18:15:09 JST
    -   表を追加
