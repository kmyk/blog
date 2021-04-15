---
redirect_from:
  - /writeup/algo/etc/icpc-2018-domestic-d/
layout: post
date: 2018-07-10T13:04:00+09:00
tags: [ "competitive", "writeup", "icpc", "exhaustive-search" ]
"target_url": [ "http://icpc.iisf.or.jp/past-icpc/domestic2018/contest/all_ja.html", "http://icpc.iisf.or.jp/past-icpc/domestic2018/judgedata/D/" ]
---

# ACM-ICPC 2018 国内予選: D. 全チームによるプレーオフ

## solution

枝刈り全探索。DFS的にやって葉を数える。サンプルに最大ケースがあり、操作回数はだいたいそれくらい。計算量の形では$n$の指数だろうが詳細は不明。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i,n) for (int i = 0; (i) < (n); ++(i))
#define REP3(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

tuple<int, int, int> count_stat(const string & s) {
    int n = s.length();
    int w = 0, l = 0, q = 0;
    REP (x, n) {
        switch (s[x]) {
            case 'W': case 'w': ++ w; break;
            case 'L': case 'l': ++ l; break;
            case '?': ++ q; break;
            default: break;
        }
    }
    return make_tuple(w, l, q);
}
bool check_stat(const string & s) {
    int w, l; tie(w, l, ignore) = count_stat(s);
    int k = (s.length() - 1) / 2;
    return (w <= k) and (l <= k);
}

int main() {
    while (true) {
        // input
        int n; cin >> n;
        if (n == 0) break;
        int m; cin >> m;
        vector<string> a(n, string(n, '?'));
        REP (z, n) a[z][z] = '-';
        REP (i, m) {
            int x, y; cin >> x >> y;
            -- x; -- y;
            a[x][y] = 'W';
            a[y][x] = 'L';
        }
        cerr << "n = " << n << endl;
        cerr << "m = " << m << endl;

        // solve
        ll cnt = 0;
        function<void (int)> go = [&](int y) {
            if (y == n) {
                ++ cnt;
                return;
            }
            REP3 (z, y, n) {
                if (not check_stat(a[y])) {
                    return;
                }
            }
            int w, l, q; tie(w, l, q) = count_stat(a[y]);
            int k = (n - 1) / 2 - w;
            assert (0 <= k and k <= q);
            REP (s, 1 << q) if (__builtin_popcount(s) == k) {
                assert (__builtin_popcount(s) == k);
                // update
                int i = 0;
                REP3 (x, y + 1, n) if (a[y][x] == '?') {
                    a[x][y] = (s & (1 << i)) ? 'l' : 'w';
                    ++ i;
                }
                // recur
                go(y + 1);
                // revert
                REP3 (x, y + 1, n) if (a[y][x] == '?') {
                    a[x][y] = '?';
                }
            }
        };
        go(0);

        // output
        cout << cnt << endl;
        cerr << "answer = " << cnt << endl;
    }
    return 0;
}
```
