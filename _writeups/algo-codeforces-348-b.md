---
layout: post
redirect_from:
  - /writeup/algo/codeforces/348-b/
  - /blog/2016/03/29/cf-348-b/
date: 2016-03-29T23:12:30+09:00
tags: [ "competitive", "writeup", "codeforces", "lcm" ]
"target_url": [ "http://codeforces.com/contest/348/problem/B" ]
---

# Codeforces Round #202 (Div. 1) B. Apple Tree

## 解法

部分木ごとにbalancedな最大の重さを計算する。lcm。$O(V + E)$。

子である部分木が$l \ge 1$個あるとする。それぞれ重さ$w_i$を持ち、その重さを$p_i$刻みでしか変化させられないとする。
$p = {\rm lcm} \\{ p_i \mid i \lt l \\}$とすると、統合後の部分木のひとつあたりの重さ$w = \max \\{ w \mid (\exists n. w = n \cdot p) \land (\forall i. w \le w_i) \\}$。
この部分木全体では重さ$w \cdot l$で、$p \cdot l$刻みでしか変化できない。

## 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
ll gcd(ll a, ll b) { if (b < a) swap(a,b); while (a) { ll c = a; a = b % c; b = c; } return b; }
ll lcm(ll a, ll b) { return (a * b) / gcd(a,b); }
int main() {
    int n; cin >> n;
    vector<ll> a(n); repeat (i,n) cin >> a[i];
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int x, y; cin >> x >> y; -- x; -- y;
        g[x].push_back(y);
        g[y].push_back(x);
    }
    function<pair<ll,ll> (int, int)> rec = [&](int i, int prv) {
        vector<ll> ws, ps;
        for (int j : g[i]) if (j != prv) {
            ll w, p; tie(w, p) = rec(j,i);
            ws.push_back(w);
            ps.push_back(p);
        }
        int l = ws.size();
        if (l == 0) return make_pair(a[i], 1ll);
        ll w = *min_element(ws.begin(), ws.end());
        ll p = 1; for (ll q : ps) {
            p = lcm(p, q);
            if (w < p) return make_pair(0ll, 1ll);
        }
        w = w / p * p;
        return make_pair(w * l, p * l);
    };
    ll ans = accumulate(a.begin(), a.end(), 0ll) - rec(0, -1).first;
    cout << ans << endl;
    return 0;
}
```
