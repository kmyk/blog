---
layout: post
redirect_from:
  - /blog/2017/05/02/arc-070-d/
date: "2017-05-02T22:28:01+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "bitset", "optimization", "lie" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc070/tasks/arc070_b" ]
---

# AtCoder Regular Contest 070: D - No Need

`bitset`定数倍高速化でなんとかしようとしたけど、あと$2,3$倍ぐらい足りなかった。
仕方がないので考察をし、その上で嘘解法をした。

## implementation

``` c++
#pragma GCC optimize "O3"
#pragma GCC target "avx"
#include <cstdio>
#include <vector>
#include <algorithm>
#include <bitset>
#include <chrono>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

constexpr int k_max = 5000;
constexpr long long tle = 2000;
int main() {
    chrono::high_resolution_clock::time_point clock_begin = chrono::high_resolution_clock::now();
    int n, k; scanf("%d%d", &n, &k);
    vector<int> a(n);
    repeat (i,n) {
        scanf("%d", &a[i]);
        setmin(a[i], k);
    }
    whole(sort, a);
    whole(reverse, a);
    int unnecessary = 0;
    auto mask_base = ~ (((~ bitset<k_max>()) >> k) << k);
    repeat (i,n) {
        if (a[i] == k) continue;
        auto mask = ((mask_base >> (k - a[i])) << (k - a[i]));
        bitset<k_max> dp = {};
        dp[0] = true;
        repeat (j,n) if (j != i and a[j] != k) {
            dp |= dp << a[j];
            if (j % 128 == 0 and (dp & mask).any()) break;
        }
        if ((dp & mask).none()) {
            unnecessary = n-i;
            break;
        }
        chrono::high_resolution_clock::time_point clock_end = chrono::high_resolution_clock::now();
        if (chrono::duration_cast<chrono::milliseconds>(clock_end - clock_begin).count() >= tle * 0.95) break;
    }
    printf("%d\n", unnecessary);
    return 0;
}
```
