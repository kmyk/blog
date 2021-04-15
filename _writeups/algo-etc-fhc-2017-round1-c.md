---
layout: post
redirect_from:
  - /writeup/algo/etc/fhc-2017-round1-c/
  - /blog/2017/01/16/fhc-2017-round1-c/
date: "2017-01-16T03:04:33+09:00"
tags: [ "competitive", "writeup", "facebook-hacker-cup", "dp", "graph" ]
"target_url": [ "https://www.facebook.com/hackercup/problem/1800890323482794/" ]
---

# Facebook Hacker Cup 2017 Round 1: Manic Moving

## solution

DP。
$i$人載せて$j$人降ろして町$k$に居るときのコストの最小値を$\mathrm{dp}(i,j,k)$にする。
状態の表現が面倒なので再帰関数で書いた方がよい。
$O(N^3 + K)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const ll inf = ll(1e18)+9;
ll solve(int n, vector<vector<pair<int,int> > > const & g, vector<pair<int,int> > const & q) {
    vector<vector<ll> > dist = vectors(n, n, inf); { // warshall-floyd
        repeat (i,n) {
            setmin<ll>(dist[i][i], 0);
            for (auto it : g[i]) {
                int j, cost; tie(j, cost) = it;
                setmin<ll>(dist[i][j], cost);
            }
        }
        repeat (k,n) repeat (i,n) repeat (j,n) setmin(dist[i][j], dist[i][k] + dist[k][j]);
    }
    for (auto it : q) {
        int s, d; tie(s, d) = it;
        if (dist[0][s] == inf or dist[0][d] == inf) return -1;
    }
    map<tuple<int,int,int>,ll> memo;
    function<ll (int,int,int)> dp = [&](int i, int j, int x) {
        if (j == q.size()) return 0ll;
        tuple<int,int,int> key = { i, j, x };
        if (not memo.count(key)) {
            ll result = inf;
            if (i < q.size() and i+1 - j <= 2) { int y = q[i].first;  setmin(result, dist[x][y] + dp(i+1, j, y)); }
            if (j+1 <= i)                      { int y = q[j].second; setmin(result, dist[x][y] + dp(i, j+1, y)); }
            memo[key] = result;
        }
        return memo[key];
    };
    return dp(0, 0, 0);
}
int main() {
    int t; cin >> t;
    repeat (i,t) {
        int n, m, k; cin >> n >> m >> k;
        vector<vector<pair<int,int> > > g(n);
        while (m --) {
            int a, b, gas; cin >> a >> b >> gas; -- a; -- b;
            g[a].emplace_back(b, gas);
            g[b].emplace_back(a, gas);
        }
        vector<pair<int,int> > q(k);
        repeat (i,k) {
            int s, d; cin >> s >> d; -- s; -- d;
            q[i] = { s, d };
        }
        cout << "Case #" << i+1 << ": " << solve(n, g, q) << endl;
    }
    return 0;
}
```
