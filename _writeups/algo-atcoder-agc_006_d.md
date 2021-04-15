---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_006_d/
  - /writeup/algo/atcoder/agc-006-d/
  - /blog/2017/08/15/agc-006-d/
date: "2017-08-15T13:03:10+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc006/tasks/agc006_d" ]
---

# AtCoder Grand Contest 006: D - Median Pyramid Hard

多くの部分で定数倍高速化$O(N^2)$を試みたが、最良でも$5$倍足りずでだめだった。

## solution

答えに関して二分探索。
答え$a\_k \ge L$だとすると、$b\_i = (a\_i \ge L) \in \\{ 0, 1 \\}$だとして同様に作ったピラミッドの頂点も$1$であるはず。
$0, 1$なら答えは$O(N)$で求められる。
$n - 1 \equiv 0 \pmod{2}$にしておいて$2$回ずつmedianを取るように考えると楽。
全体で$O(N \log N)$。


## implementation

``` c++
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

int median(int a, int b, int c) {
    if (a > b) swap(a, b);
    return max(a, min(b, c));
}

template <typename UnaryPredicate>
int binsearch(int l, int r, UnaryPredicate p) { // [l, r), p is monotone
    assert (l < r);
    -- l;
    while (r - l > 1) {
        int m = (l + r) / 2;
        (p(m) ? r : l) = m;
    }
    return r; // = min { x in [l, r) | p(x) }, or r
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(2 * n - 1);
    repeat (x, 2 * n - 1) {
        scanf("%d", &a[x]);
    }
    // solve
    if ((n - 1) % 2 == 1) {
        vector<int> b(2 * n - 3);
        repeat (x, 2 * n - 3) {
            b[x] = median(a[x], a[x + 1], a[x + 2]);
        }
        a.swap(b);
        -- n;
    }
    int result = binsearch(1, 2 * n, [&](int limit) {
        vector<char> b(2 * n - 1);
        repeat (x, 2 * n - 1) {
            b[x] = a[x] > limit;
        }
        int result = b[n - 1];
        int dist = 2 * n;
        repeat (x, (2 * n - 1) - 2) {
            if ((b[x] != b[x + 1] and b[x + 1] == b[x + 2])
                    or (b[x] == b[x + 1] and b[x + 1] != b[x + 2])) {
                int ndist = abs((x + 1) - (n - 1));
                if (ndist < dist) {
                    dist = ndist;
                    result = b[x + 1];
                }
            }
        }
        return not result;
    });
    // output
    printf("%d\n", result);
    return 0;
}
```
