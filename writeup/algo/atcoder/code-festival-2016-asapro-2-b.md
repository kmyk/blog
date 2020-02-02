---
layout: post
alias: "/blog/2016/12/12/code-festival-2016-asapro-2-b/"
date: "2016-12-12T12:41:39+09:00"
title: "CODE FESTIVAL 2016 Elimination Tournament Round 2: B - 魔法使い高橋君 / Takahashi the Magician"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-tournament-round2-open/tasks/asaporo_a" ]
---

これを$30$分コンテストで出すの、解かせる気あるのかという気持ちになる。

## solution

隣接する$a,b$について$k = \min \\{ k \mid a \lt f^k(b) \\}$を求めればよいことが分かる。計算量は$O(NM \sqrt{\max A\_(i,j)})$ぐらいな気がする。

まず、$ a \lt b \iff f(a) \lt f(b) $である。
$(\Rightarrow)$は明らか。$(\Leftarrow)$は$(\Rightarrow)$から対偶とって適当にする。

さらに、$ k = \min \\{ k \mid a \lt f^{k}(b) \\} \implies \forall l. \; f^{l}(a) \lt f^{k+l}(b) $である。
$k$の取り方より$a \ge f^{k-1}(b)$であり、上の性質より$f^{l}(a) \ge f^{k+l-1}(b)$。
同様に$a \lt f^{k}(b)$であり、$f^{l}(a) \lt f^{k+l}(b)$。

これより、$a_0, a_1, \dots, a\_{N-1}$を組ごとに順に見ていって、それまでの$k$の総和の総和を取ればよい。
ただし元々$a \lt b$な組に関しては、$k = \min \\{ k \mid b \lt f^k(a) \\}$を計算して適当に引いたりする。
$a = f^k(b)$となるような$k$がある場合、$a \lt b$と$a \ge b$の時ですこしずれてくるので注意。

よって、単に与えられたままの$a,b$に対し$k = \min \\{ k \mid a \lt f^k(b) \\}$を計算できればよい。
これは各$a_i, b_i \le 10^9$であるので、いい感じにやれば間に合う。
つまり$a_0 \le b_0$を確認し、$a_1 \le b_1 + k b_0$となるような最小の$k$を求め、$a_1 = b_1 + k b_0$なら$a_i \lt b_i$となった$i$以降は省略しつつ適当に試す、などとする。


## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
pair<int, bool> func(vector<ll> const & a, vector<ll> b) {
    int w = a.size();
    if (a < b) {
        return { 0, false };
    } else if (a[0] > b[0]) {
        return { -1, false };
    } else {
        assert (a[0] == b[0]);
        if (w == 1) {
            return { -1, false };
        } else {
            assert (b[0] >= 1);
            assert (a[1] >= b[1]);
            ll k = (a[1] - b[1] + b[0]-1) / b[0];
            if (b[1] + k * b[0] > a[1]) {
                return { k, false };
            } else {
                assert (b[1] + k * b[0] == a[1]);
                if (w == 2) {
                    return { k, true };
                } else {
                    repeat (j,k) {
                        repeat (i,w-1) {
                            if (b[i] > a[i]) break;
                            b[i+1] += b[i];
                            assert (b[i+1] >= 1);
                        }
                        if (b[2] > a[2]) {
                            b[1] = a[1];
                            break;
                        }
                    }
                    return { k + (a > b), a == b };
                }
            }
        }
    }
}
int main() {
    int h, w; cin >> h >> w;
    vector<vector<ll> > f = vectors(h, w, ll());
    repeat (y,h) repeat (x,w) cin >> f[y][x];
    ll ans = 0;
    ll acc = 0;
    repeat (y,h-1) {
        vector<ll> const & a = f[y];
        vector<ll> const & b = f[y+1];
        if (a < b) {
            int k; bool is_just; tie(k, is_just) = func(b, a);
            if (k == -1) {
                acc = 0;
            } else {
                acc = max<int>(0, acc-k+1);
            }
        } else {
            int k; bool is_just; tie(k, is_just) = func(a, b);
            if (k == -1) {
                ans = -1;
                break;
            } else {
                acc += k + is_just;
            }
        }
        ans += acc;
    }
    cout << ans << endl;
    return 0;
}
```
