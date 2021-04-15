---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_085_d/
  - /writeup/algo/atcoder/arc-085-d/
  - /blog/2017/12/31/arc-085-d/
date: "2017-12-31T16:04:26+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "coordinate-compression" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc085/tasks/arc085_b" ]
---

# AtCoder Regular Contest 085: D - ABS

頭のいい人たちはみんな$O(1)$をしてたが、私は思考停止$O(N^2)$DP。

## solution

手番が$p$で山札が$i$枚目まで引かれもう一方の人の手札が$b$である状態から始めたときの結果を$\mathrm{dp}(p, i, b)$としてDP。座標圧縮をすれば$O(N^2)$。

どうせ無理矢理な解なのだし、memo化再帰と`std::map`とかでやるのがおすすめ。

## implementation

``` c++
#include <climits>
#include <cstdio>
#include <functional>
#include <map>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

int main() {
    // input
    int n, z, w; scanf("%d%d%d", &n, &z, &w);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    // solve
    vector<map<int, int> > memo_fst(n);
    vector<map<int, int> > memo_snd(n);
    function<int (bool, int, int, int)> go = [&](bool is_first, int i, int z, int w) {
        if (i == n) {
            return abs(z - w);
        }
        if (is_first) {
            if (memo_fst[i].count(w)) return memo_fst[i][w];
            int acc = INT_MIN;
            repeat_from (j, i, n) {
                setmax(acc, go(false, j + 1, a[j], w));
            }
            return memo_fst[i][w] = acc;
        } else {
            if (memo_snd[i].count(z)) return memo_snd[i][z];
            int acc = INT_MAX;
            repeat_from (j, i, n) {
                setmin(acc, go(true, j + 1, z, a[j]));
            }
            return memo_snd[i][z] = acc;
        }
    };
    int result = go(true, 0, z, w);
    // output
    printf("%d\n", result);
    return 0;
}
```
