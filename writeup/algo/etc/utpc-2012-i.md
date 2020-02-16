---
layout: post
redirect_from:
  - /blog/2018/01/01/utpc-2012-i/
date: "2018-01-01T10:51:21+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "shortest-path", "dijkstra", "divide-and-conquer" ]
"target_url": [ "https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_09" ]
---

# 東京大学プログラミングコンテスト2012: I - 最短路クエリ

## 反省

はいsegment木って言って書いたら迂回のない(つまり$W \le 2$の)場合しか解けないやつだった。
入力例$2$から分かるように、$(SX, SY)$から$(TX, TY)$へ行く場合でも長方形$(SX, SY, TX, TY)$の外に出ることはある。

この勘違いがなくても解けてなかったが、つまりは広義の重心分解で手法としては分かりやすいので、次はきっと解けるはず。

## solution

Dijkstra + 分割統治。
$H \le 10^4$と大きいのに対し$W \le 10$と小さい。
木の重心分解のように、区間の中央の行を通るか通らないかで分けていく。
中央を通るようなものなら中央の点からの最短距離を繋ぎ合わせればよい。$O(HW \log HW)$のDijkstra法を$W$回。
中央を通らないものについては半分になった区間について再帰。これで計算量が落ちる。
前処理$O(HW^2 \log HW \log H)$、クエリ全体で$O(QW \log H)$。

## implementation

`shared_ptr<...>` で持たないと`map`の内部で発生するコピーにより計算量が上がって死ぬ

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
using ll = long long;
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };

int main() {
    // input
    int w, h, queries; scanf("%d%d%d", &w, &h, &queries);
    auto a = vectors(h, w, int());
    REP (y, h) REP (x, w) {
        scanf("%d", &a[y][x]);
    }
    constexpr int MAX_W = 10;
    assert (w <= MAX_W);

    // prepare
    map<tuple<int, int, int>, shared_ptr<array<vector<array<ll, MAX_W> >, MAX_W> > > memo;
    auto shortest_path = [&](int l, int y1, int r) {
        assert (l <= y1 and y1 < r);
        auto key = make_tuple(l, y1, r);
        if (memo.count(key)) return memo[key];
        memo[key] = make_shared<array<vector<array<ll, MAX_W> >, MAX_W> >();
        auto & dist = *memo[key];
        // dijkstra
        REP (x1, w) {
            dist[x1].resize(r - l);
            REP3 (y2, l, r) REP (x2, w) dist[x1][y2 - l][x2] = LLONG_MAX;
        }
        reversed_priority_queue<tuple<ll, int, int> > que;
        REP (x1, w) {
            dist[x1][y1 - l][x1] = a[y1][x1];
            que.emplace(a[y1][x1], y1, x1);
            while (not que.empty()) {
                ll cur; int y2, x2; tie(cur, y2, x2) = que.top(); que.pop();
                if (dist[x1][y2 - l][x2] < cur) continue;
                REP (i, 4) {
                    int y3 = y2 + dy[i];
                    int x3 = x2 + dx[i];
                    if (y3 < l or r <= y3 or x3 < 0 or w <= x3) continue;
                    ll nxt = cur + a[y3][x3];
                    if (nxt < dist[x1][y3 - l][x3]) {
                        dist[x1][y3 - l][x3] = nxt;
                        que.emplace(nxt, y3, x3);
                    }
                }
            }
        }
        return memo[key];
    };

    int sx, sy, tx, ty;
    function<ll (int, int)> solve = [&](int l, int r) {
        assert (sy <= ty);
        if (not (l <= sy and ty < r)) return LLONG_MAX;
        if (r - l == 0) return LLONG_MAX;
        int m = (l + r) / 2;
        ll acc = LLONG_MAX;
        auto const & dist = *shortest_path(l, m, r);
        REP (x, w) {
            chmin(acc, dist[x][sy - l][sx] + dist[x][ty - l][tx] - a[m][x]);
        }
        if (r - l != 1) {
            chmin(acc, solve(l, m));
            chmin(acc, solve(m, r));
        }
        return acc;
    };

    // serve
    while (queries --) {
        scanf("%d%d%d%d", &sx, &sy, &tx, &ty);
        -- sx; -- sy; -- tx; -- ty;
        if (sy > ty) {
            swap(sy, ty);
            swap(sx, tx);
        }
        auto dist = solve(0, h);
        printf("%lld\n", dist);
    }
    return 0;
}
```
