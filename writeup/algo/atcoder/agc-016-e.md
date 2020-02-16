---
layout: post
redirect_from:
  - /blog/2017/06/26/agc-016-e/
date: "2017-06-26T03:47:11+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc016/tasks/agc016_e" ]
---

# AtCoder Grand Contest 016: E - Poor Turkeys

検証用に$O(2^M)$愚直解を投げるときは`1 << m`でoverflowしないよう注意が必要であることが知られている。

## solution

関係$R \subseteq N \times N$ を $x R y \iff (\text{鳥$x$が生きているなら鳥$y$は死んでいないといけない})$で定義する。
$x R x \iff (\text{鳥$x$はどうやっても死ぬ})$となることに注意。
これを順に更新していけば$O(N(N + M))$。

クエリ$(x, y)$が来たとして関係$R$を更新することを考える。
制約は減少することはない。
明らかに$x R y$と$y R x$が加わる。
任意の$z$に対し、$z R x$なら$z R y$、$x R z$なら$y R z$など、推移性を満たすように拡張する。
これとは別に$x R x$なら$y R y$、$y R y$なら$x R x$も加える。

こうして全部更新し終わったあと、いい感じの$(x, y)$の組を数えればよい。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<int> xs(m), ys(m);
    repeat (i, m) {
        scanf("%d%d", &xs[i], &ys[i]);
        -- xs[i];
        -- ys[i];
    }
    // solve
    auto rel = vectors(n, n, bool()); // xRy iff (if x alives, then y must die)
    repeat (i, m) {
        int x = xs[i];
        int y = ys[i];
        repeat (z, n) {
            if (rel[y][z]) rel[x][z] = true;
            if (rel[x][z]) rel[y][z] = true;
            if (rel[z][y]) rel[z][x] = true;
            if (rel[z][x]) rel[z][y] = true;
        }
        if (rel[y][y]) rel[x][x] = true;
        if (rel[x][x]) rel[y][y] = true;
        rel[x][y] = true;
        rel[y][x] = true;
    }
    // output
    int result = 0;
    repeat (j, n) repeat (i, j) {
        if (rel[j][j]) continue;
        if (rel[i][i]) continue;
        result += not (rel[i][j] or rel[j][i]);
    }
    printf("%d\n", result);
    return 0;
}
```
