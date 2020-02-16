---
category: blog
layout: post
date: "2017-04-01T04:10:17+09:00"
tags: [ "optimization", "cache" ]
---

# cache lineの衝突による速度の低下を確認した

## 概要

密行列積を計算する単純なコードを書き、行列の大きさが$2$羃のときとそうでないときで速度比較をした。
$2$羃のとき、明らかな速度の低下が見られた。

## 結果

```
$ clang++ -std=c++14 -O2 a.cpp -DN=1030

$ ./a.out
3.212000 msec

$ clang++ -std=c++14 -O2 a.cpp -DN=1024

$ ./a.out
12.461000 msec
```

備考として、密行列積のloop interchangeをすると速度差は消える。
少ない数のcache lineしか使わないようになるため、衝突が発生しないのであろう。

## implementation

``` c++
#include <cstdio>
#include <random>
#include <chrono>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

double a[N][N];
double b[N][N];
double c[N][N];
void dgemm() {
    repeat (y,N) {
        repeat (x,N) {
            repeat (z,N) {
                c[y][x] += a[y][z] * b[z][x];
            }
        }
    }
}

int main() {
    // init matrices
    random_device device;
    default_random_engine gen(device());
    uniform_real_distribution<double> dist;
    repeat (y,N) repeat (x,N) a[y][x] = dist(gen);
    repeat (y,N) repeat (x,N) b[y][x] = dist(gen);

    // flush cache
    constexpr int dirty = 128 * 1024 * 1024;
    void * volatile p = malloc(dirty);
    repeat (i, dirty) ((char *)p)[i] = gen() % 256;
    free(p);

    // run
    chrono::high_resolution_clock::time_point clock_begin = chrono::high_resolution_clock::now();
    dgemm();
    chrono::high_resolution_clock::time_point clock_end = chrono::high_resolution_clock::now();

    // output
    printf("%lf msec\n", chrono::duration_cast<chrono::milliseconds>(clock_end - clock_begin).count() / 1000.0);
    return 0;
}
```
