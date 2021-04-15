---
layout: post
redirect_from:
  - /writeup/algo/atcoder/cf17-relay-f/
  - /blog/2017/11/27/cf17-relay-f/
date: "2017-11-27T17:58:13+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "team-relay", "dp", "kadane-algorithm" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-relay-open/tasks/relay2_f" ]
---

# Code Festival Team Relay: F - Capture

本番で担当。
$s\_i \le 10^9$だが$x\_i \le 10^{15}$なぜか変に大きく、入力取る部分でoverflowさせて焦った。

## solution

DP。端から舐めていけばその時点での最高だけ持てばよい感じになる。つまり[Kadane's algorithm](https://en.wikipedia.org/wiki/Maximum_subarray_problem#Kadane's_algorithm_(Algorithm_3:_Dynamic_Programming\))。$O(N)$。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

int main() {
    // input
    int n; scanf("%d", &n);
    vector<ll> x(n), s(n); repeat (i, n) scanf("%lld%lld", &x[i], &s[i]);
    // solve
    ll result = s[0];
    ll acc = s[0];
    repeat (i, n - 1) {
        acc -= x[i + 1] - x[i];
        setmax(acc, 0ll);
        acc += s[i + 1];
        setmax(result, acc);
    }
    // output
    printf("%lld\n", result);
    return 0;
}
```
