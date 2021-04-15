---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_063_e/
  - /writeup/algo/atcoder/arc-063-e/
  - /blog/2016/11/06/arc-063-e/
date: "2016-11-06T22:48:20+09:00"
tags: [ "competitive", "wirteup", "atcoder", "arc", "tree", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc063/tasks/arc063_c" ]
---

# AtCoder Regular Contest 063: E - 木と整数 / Integers on a Tree

この問題から開いて書いて提出したら$1$WA生えて焦った。

## solution

木DPで各頂点が取りうる値の区間を全て計算する。$O(N)$。

まず点$v$のみに制約$p_v$がある場合を考えよう。
この制約から影響される他の点の制約は(さらに他の点は無視するとして)$p_u - p_v \le d(u, v) \land p_u - p_v \equiv d(u, v) \pmod 2$である。
$1$辺辿ると値はちょうど$\pm 1$され、範囲は広がるが偶奇が反転するのでこうなる。
この制約は集合$p_u \in \\{ p_v - d(u, v), p_v - d(u, v) + 2, \dots, p_v + d(u, v) \\}$として表わせる。
偶奇制約は別に確認するとすれば、区間$p_u \in [p_v - d(u, v), p_v + d(u, v)]$として$2$整数で持てる。

制約は複数の点を中心に存在する。
影響されてきた制約の合成を考えよう。
これは単に制約となる集合の共通部分である。
偶奇が異なれば空になり、そうでなければ区間の端点の最大値最小値を取ればよい。

適当な根を決めて再帰的に、各部分木の根の合成された(それが満たされればその部分木全体に値を割り当てられるような)制約を決めていく。
これは単に各点で子の制約を合成するだけになる。
そうして求まった根の制約を適当に満たせば、逆向きに制約を伝播させつつ値を構成すればよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
const int inf = 1e9+7;
int main() {
    int n; cin >> n;
    vector<vector<int> > g(n);
    repeat (i, n-1) {
        int a, b; cin >> a >> b; -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    int k; cin >> k;
    vector<int> l(n, - inf), r(n, inf); // [l, r)
    repeat (i, k) {
        int v, p; cin >> v >> p; -- v;
        l[v] = p;
        r[v] = p+1;
    }
    const int root = 0;
    function<bool (int, int)> go1 = [&](int i, int parent) {
        vector<int> ls, rs;
        ls.push_back(l[i]);
        rs.push_back(r[i]);
        for (int j : g[i]) if (j != parent) {
            if (not go1(j, i)) return false;
            ls.push_back(max(- inf, l[j] - 1));
            rs.push_back(min(  inf, r[j] + 1));
        }
        l[i] = *whole(max_element, ls); for (int lj : ls) if (lj != - inf and lj % 2 != l[i] % 2) return false;
        r[i] = *whole(min_element, rs); for (int rj : rs) if (rj !=   inf and rj % 2 != r[i] % 2) return false;
        if (r[i] - l[i] <= 0) return false;
        return true;
    };
    bool possible = go1(root, -1);
    cout << (possible ? "Yes" : "No") << endl;
    if (possible) {
        vector<int> result(n, - inf);
        function<void (int, int)> go2 = [&](int i, int parent) {
            result[i] = l[i];
            for (int j : g[i]) if (j != parent) {
                setmax(l[j], l[i] - 1);
                go2(j, i);
            }
        };
        go2(root, -1);
        for (int it : result) cout << it << endl;
    }
    return 0;
}
```
