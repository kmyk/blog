---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-quala-d/
  - /blog/2016/09/25/code-festival-2016-quala-d/
date: "2016-09-25T03:26:27+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2016-quala/tasks/codefestival_2016_qualA_d" ]
---

# CODE FESTIVAL 2016 qual A: D - マス目と整数 / Grid and Integers

解けず。
A,B,Cやるだけ早解きD,E絶望のパターンは差がでないから困る。
あと部分点早解きも戦略ミスするので止めてほしい。

個人的に通って欲しい人がいくらかいるので順位を眺めたのですが、事故ったぽいひとり以外はみな$300$位台で、安心はできないがそこまで不安でもないのでよかったです。

## problem

空欄のある行列が与えられるので、以下の制約を満たすように埋めれるか判定する問題。

-   全要素は非負整数
-   以下のように$2\times 2$に並んでいる部分の全てに対し、$a+d = b+c$が成り立つ

$$ \begin{pmatrix}
    a & b \\\\
    c & d
\end{pmatrix} $$

## solution

$H \times W$の行列$A = \\{ a\_{y,x} \\}$が制約を満たすとすると、ある長さ$H$の数列$p = ( p_0, p_1, \dots, p\_{H-1} )$と長さ$W$の数列$q = ( q_0, q_1, \dots, q\_{W-1} )$が存在して、$a\_{y,x} = p_y + q_x$。
これは、 なめなのが気持ち悪いから揃えたいので移項してみる、$2 \times 2$でなくて$2 \times 3$だとどういう制約になるか考えて整理する、などから始めて辿り着ける。

この数列$p, q$を構成できるか試せばよい。
点$a\_{y,x}, a\_{y',x}$を見たとき$a\_{y,x} - p_y = q_x = a\_{y',x} - p\_{y'}$という式が立つ。$x$方向にも同様。
ある点$a\_{y,x}$を決め、一旦$p_y = a\_{y,x}, q_x = 0$として、上の式を使い上下左右にこれを伝播させていけばよい。
連結成分ごとにこれを行い、別個に求める。

全要素は非負整数という制約もある。
これを満たすのは$\min p + \min q \ge 0$と同値であるが、このとき各$p_i, q_i$は全て非負にできる。
$\min p + \min q \ge 0 \land \min p \lt 0$が言えていれば、数列$p$から$q$へ$\min p$分だけ移す、つまり数列$p,q$の各要素に$- \min p, \min p$足すことで制約を保ちつつ$\min p \ge 0, \min q \ge 0$にできる。
グラフの連結成分ごとにこれを行っておく。
それぞれはこの制約を満たしていても問題になるのは、$\min p_1 + \min q_1 \ge 0 \land \min p_2 + \min q_2 \ge 0 \land \min p_1 \lt 0 \land \min q_2 \lt 0$の場合で、$\min (p_1 \oplus p_2) + \min (q_1 \oplus q_2) = \min p_1 + \min q_2 \lt 0$となり仮定が壊れる。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <set>
#include <map>
#include <queue>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }

const ll inf = ll(1e18)+9;
int main() {
    // input
    int h, w; scanf("%d%d", &h, &w);
    int n; scanf("%d", &n);
    vector<tuple<int,int,int> > q(n);
    map<int,map<int,int> > fh;
    map<int,map<int,int> > fw;
    repeat (i,n) {
        int y, x, a; scanf("%d%d%d", &y, &x, &a); -- y; -- x;
        q[i] = { y, x, a };
        fh[y][x] = a;
        fw[x][y] = a;
    }
    // compute
    bool ans = true;
    vector<ll> ph(h, inf);
    vector<ll> pw(w, inf);
    auto go = [&](int sy, int sx, int sa) {
        assert (ans);
        assert (ph[sy] == inf);
        assert (pw[sx] == inf);
        queue<tuple<int,int> > que;
        vector<bool> usedh(h, false);
        vector<bool> usedw(w, false);
        set<int> usedys;
        set<int> usedxs;
        que.push(make_tuple(sy, sx));
        ph[sy] = sa; pw[sx] = 0;
        while (not que.empty()) {
            int y, x; tie(y, x) = que.front(); que.pop();
            int a = fh[y][x];
            usedys.insert(y);
            usedxs.insert(x);
            if (pw[x] != inf and not usedh[y]) {
                usedh[y] = true;
                for (auto it : fh[y]) {
                    int nx, na; tie(nx, na) = it;
                    if (pw[nx] == inf) {
                        assert (pw[x] != inf);
                        pw[nx] = pw[x] - a + na;
                        if (not usedw[nx]) que.push(make_tuple(y, nx));
                    } else {
                        if (pw[nx] != pw[x] - a + na) { ans = false; return; }
                    }
                }
            }
            if (ph[y] != inf and not usedw[x]) {
                usedw[x] = true;
                for (auto it : fw[x]) {
                    int ny, na; tie(ny, na) = it;
                    if (ph[ny] == inf) {
                        ph[ny] = ph[y] - a + na;
                        if (not usedh[ny]) que.push(make_tuple(ny, x));
                    } else {
                        if (ph[ny] != ph[y] - a + na) { ans = false; return; }
                    }
                }
            }
        }
        ll minh = inf; for (int y : usedys) setmin(minh, ph[y]);
        ll minw = inf; for (int x : usedxs) setmin(minw, pw[x]);
        if (minh + minw < 0) { ans = false; return; }
        if (minh < 0) {
            for (int y : usedys) if (ph[y] != inf) ph[y] -= minh;
            for (int x : usedxs) if (pw[x] != inf) pw[x] += minh;
        } else if (minw < 0) {
            for (int y : usedys) if (ph[y] != inf) ph[y] += minw;
            for (int x : usedxs) if (pw[x] != inf) pw[x] -= minw;
        }
    };
    repeat (i,n) {
        int y, x, a; tie(y, x, a) = q[i];
        if (ph[y] == inf and pw[x] == inf) {
            go(y, x, a);
        }
        if (not ans) break;
        if (ph[y] == inf) ph[y] = a - pw[x];
        if (pw[x] == inf) pw[x] = a - ph[y];
        if (a != ph[y] + pw[x]) { ans = false; break; }
    }
    if (ans) {
        if (*whole(min_element, ph) + *whole(min_element, pw) < 0) ans = false;
    }
    // output
    printf("%s\n", ans ? "Yes" : "No");
    return 0;
}
```
