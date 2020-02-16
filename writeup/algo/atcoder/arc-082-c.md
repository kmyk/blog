---
layout: post
redirect_from:
  - /blog/2017/09/04/arc-082-c/
date: "2017-09-04T15:19:33+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc082/tasks/arc082_a" ]
---

# AtCoder Regular Contest 082: C - Together

## solution

$X$の候補は$a\_i - 1, a\_i, a\_i + 1$のみ考えればよい。
これを全て試す。
$O(N \log N)$。

## implementation

``` c++
#include <cstdio>
#include <map>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

int main() {
    int n; scanf("%d", &n);
    map<int, int> cnt;
    repeat (i, n) {
        int a_i; scanf("%d", &a_i);
        cnt[a_i] += 1;
    }
    int result = 0;
    for (auto it : cnt) {
        for (int x : {
                    it.first - 1,
                    it.first,
                    it.first + 1 }) {
            int acc = 0;
            if (cnt.count(x - 1)) acc += cnt[x - 1];
            if (cnt.count(x    )) acc += cnt[x    ];
            if (cnt.count(x + 1)) acc += cnt[x + 1];
            setmax(result, acc);
        }
    }
    printf("%d\n", result);
    return 0;
}
```
