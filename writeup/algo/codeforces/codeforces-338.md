---
layout: post
redirect_from:
  - /writeup/algo/codeforces/codeforces-338/
  - /blog/2015/09/22/codeforces-338/
date: 2015-09-22T00:10:39+09:00
tags: [ "codeforces", "competitive", "c++", "writeup", "matrix" ]
"target_url": [ "http://codeforces.com/contest/338" ]
---

# Codeforces Round #196 (Div. 1)

茶会。1完。解けた人の数を見る限り2完したかった。

<!-- more -->

## [A. Quiz](http://codeforces.com/contest/338/problem/A) {#a}

解けた。普段より実装が少し多い気がした。行列ライブラリぐらい用意しておけということか。

貪欲を試して上手くいくことを確認すれば後はそのまま流れで解ける。

### 問題

`o`と`x`を$n$個並べる。内$m$個が`o`で残りは`x`である。
その並びを左から順に見ていく。`o`であれば1点を得る。$k$回連続で`o`であれば(1点を得た後の)現在の得点を2倍する(`o`の出た回数のカウントは0に戻す)。
$n, m, k$が与えられたとき、得点の最小値を求める。

### 解法

`o` `x` の配置は貪欲に置けばよい。後ろになるほど重要度が大きいので$k-1$つの`o`ごとに`x`を置き、`ooooooooooooooo...ooooooooooxoooxooox...xoooxoooxoooxooo`のようになる。
このとき最左の`x`から始まる`xoooxooox...xoooxoooxoooxooo`の部分は$(n - m) k$個で、残りの部分は$n - (n - m) k$個の連続する`o`となる。
こうなれば後は計算するだけである。

しかし$n = 1000000000, m = 0, k = 2$の場合等は、単に$\frac{n - (n - m) k}{k}$回のloopを回すとTLEしてしまう。
なので行列の繰り返し二乗法を用いる。$O(\log n)$

### 解答

``` c++
#include <iostream>
#include <array>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
constexpr ll mod = 1000000009;
template <typename T, size_t N, size_t M>
struct matrix { T at[N][M]; };
template <typename T, size_t A, size_t B, size_t C>
matrix<T,A,C> operator * (matrix<T,A,B> const & p, matrix<T,B,C> const & q) {
    matrix<T,A,C> r = {};
    repeat (y,A) {
        repeat (z,B) {
            repeat (x,C) {
                r.at[y][x] += p.at[y][z] * q.at[z][x];
                r.at[y][x] %= mod;
            }
        }
    }
    return r;
}
template <typename T, size_t A, size_t B>
array<T,A> operator * (matrix<T,A,B> const & p, array<T,B> const & q) {
    array<T,A> r = {};
    repeat (y,A) {
        repeat (z,B) {
            r[y] += p.at[y][z] * q[z];
            r[y] %= mod;
        }
    }
    return r;
}
int main() {
    ll n, m, k; cin >> n >> m >> k;
    ll x = n - m;
    ll l = n - x * k;
    if (l <= 0) {
        cout << m << endl;
    } else {
        ll y = 0;
        matrix<ll,3,3> f = { { { 1, 0, 0 }, { 0, 1, 0 }, { 0, 0, 1 } } };
        matrix<ll,3,3> e = { { { 2, 0, 2*k }, { 0, 1, 0 }, { 0, 0, 1 } } };
        for (int i = 0; (1ll << i) <= (l / k); ++ i) {
            if ((1ll << i) & (l / k)) {
                f = f * e;
            }
            e = e * e;
        }
        array<ll,3> v { { 0, 0, 1 } };
        y += (f * v)[0];
        y %= mod;
        y += l % k;
        y %= mod;
        y += x * (k - 1);
        y %= mod;
        cout << y << endl;
    }
    return 0;
}
```

`template <typename T, int A, int B> ...`ってしたら、`std::array`は`unsigned`な値を取るけどこれは`signed`だから合わないね、ってなエラーが出た。

## [B. Book of Evil](http://codeforces.com/contest/338/problem/B) {#b}

解法は思い付くも本番中には書けず。
実装面倒だし、手元ではstack溢れてSEGV飛ぶし(codeforces鯖では大丈夫だった)、つらかった。
そう難しい問題ではないと思うのだが。

印の付いた頂点を中心に考えてもだめ、各頂点を中心に考えてもだめ、じゃあ分割するしかない、という流れで思い付く。

### 問題

木が与えられる。その木の頂点のいくつかは印が付いており、また距離$d$も与えられる。その木の頂点で、印の付いた頂点のどれとも距離が$d$以下のもの、の数を求める。

### 解法

各頂点に関して、その各辺に関して、その頂点からその辺の方向に最も遠い印の付いた頂点の距離を求める。
これは根を固定して2回のdfsで計算できる。$O(n)$

特に、1回目のdfsで子孫方向への距離を求め、2回目で先祖方向への距離を求める。

### 解答

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <algorithm>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
int foo(int v, int p, vector<int> & parent, vector<vector<int> > & farthest, set<int> const & q, vector<vector<int> > const & g) {
    int result = q.count(v) ? 1 : 0;
    repeat (i, int(g[v].size())) {
        const int u = g[v][i];
        if (u == p) {
            parent[v] = i;
        } else {
            farthest[v][i] = foo(u, v, parent, farthest, q, g);
            result = max(result, farthest[v][i] == 0 ? 0 : farthest[v][i] + 1);
        }
    }
    return result;
}
void bar(int v, int p, vector<int> const & parent, vector<vector<int> > & farthest, set<int> const & q, vector<vector<int> > const & g) {
    vector<pair<int,int> > a;
    a.emplace_back(q.count(v) ? 1 : 0, v);
    repeat (i, int(g[v].size())) {
        a.emplace_back(farthest[v][i] == 0 ? 0 : farthest[v][i] + 1, i);
    }
    if (a.size() == 1) return;
    sort(a.rbegin(), a.rend());
    repeat (i, int(g[v].size())) {
        const int u = g[v][i];
        if (u != p) {
            farthest[u][parent[u]] = a[0].second != i ? a[0].first : a[1].first;
            bar(u, v, parent, farthest, q, g);
        }
    }
}
int main() {
    int n, m, d; cin >> n >> m >> d;
    if (d == 0) {
        cout << (m == 1 ? 1 : 0) << endl;
        return 0;
    }
    vector<int> p(m); repeat (i,m) { cin >> p[i]; -- p[i]; }
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int a, b; cin >> a >> b; -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    set<int> q; repeat (i,m) q.insert(p[i]);
    vector<int> parent(n);
    vector<vector<int> > farthest = g; // copy the structure
    foo(0, -1, parent, farthest, q, g);
    bar(0, -1, parent, farthest, q, g);
// repeat (i,n) { cout << i+1 << " : "; repeat (j, int(g[i].size())) cout << " " << g[i][j]+1 << "(" << farthest[i][j] << ")"; cout << endl; }
    int result = 0;
    repeat (i,n) {
        if (*max_element(farthest[i].begin(), farthest[i].end()) <= d) {
            result += 1;
        }
    }
    cout << result << endl;
    return 0;
}
```

-   stack溢れるからとlocal変数をstaticにして回ったりもしたのに、judge側ではなぜか動いてしまってなんとも言えない気持ちに。
-   `farthest[v][i] == 0 ? 0 : farthest[v][i] + 1`ってなってるところを単に`farthest[v][i] + 1`しててバグらせていた。
    -   愚直解とランダム生成ケースで殴ったのに掛からず、結局コードを睨んで見つけた。木の生成方法がまずかったのだろうか。
