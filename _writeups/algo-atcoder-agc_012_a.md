---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_012_a/
  - /writeup/algo/atcoder/agc-012-a/
  - /blog/2017/06/14/agc-012-a/
date: "2017-06-14T11:27:30+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc012/tasks/agc012_a" ]
---

# AtCoder Grand Contest 012: A - AtCoder Group Contest

## solution

貪欲。$O(N \log N)$。

強さが$x\_1 \le x\_2 \le x\_3, \; y\_1 \le y\_2 \le y\_3$な組$(x\_1, x\_2, x\_3), \; (y\_1, y\_2, y\_3)$があるとする。不等式を保ったまま適当に組み換えて$\max \\{ x\_1, y\_1 \\} \le \min \\{ x\_2, y\_2 \\}$にできて、このとき$x\_2 + y\_2$が最大で$y\_3 \le x\_2 \lor x\_3 \le y\_2$となる。
つまり長さが$3N$のとき、sortした後に組$(a\_1, a\_{3N-1}, a\_{3N})$で作るのが最善。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

int main() {
    int n; scanf("%d", &n);
    vector<int> a(3*n); repeat (i, 3*n) scanf("%d", &a[i]);
    whole(sort, a);
    ll result = 0;
    repeat (i, n) {
        result += a[3*n-1 - (2*i+1)];
    }
    printf("%lld\n", result);
    return 0;
}
```
