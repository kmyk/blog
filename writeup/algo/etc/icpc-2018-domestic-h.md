---
layout: post
title: "ACM-ICPC 2018 国内予選: H. 優秀なプログラマになるには"
date: 2018-07-11T16:26:41+09:00
tags: [ "competitive", "writeup", "icpc", "dp", "tree", "knapsack-problem", "sliding-window" ]
"target_url": [ "http://icpc.iisf.or.jp/past-icpc/domestic2018/contest/all_ja.html", "http://icpc.iisf.or.jp/past-icpc/domestic2018/judgedata/H/" ]
---

## solution

[木上のナップサック問題, @tmaehara - Qiita](https://qiita.com/tmaehara/items/4b2735e56843bad89949) を読んでください。
記事とのギャップとしては「アイテムが$1$種類で費用も$1$の個数制限付きナップサック問題であって初期配列が指定されるものを$O(N)$で解きたい」部分がありますが、sliding windowを用いて$\mathrm{dp}(x) - s_i x$のように傾斜を付けた配列の最大値を取得してやれば済みます。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP3R(i, m, n) for (int i = int(n) - 1; (i) >= int(m); -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

template <typename T, class Compare = less<T> >
class sliding_window {
    deque<pair<int, T> > data;
    Compare compare;
public:
    sliding_window(Compare const & a_compare = Compare())
        : compare(a_compare) {}
    T front() {  // O(1), minimum
        return data.front().second;
    }
    void push_back(int i, T a) {  // O(1) amortized.
        while (not data.empty() and compare(a, data.back().second)) {
            data.pop_back();
        }
        data.emplace_back(i, a);
    }
    void pop_front(int i) {
        if (data.front().first == i) {
            data.pop_front();
        }
    }
};

constexpr ll INF = (ll) 1e18 + 9;
int main() {
    while (true) {
        // input
        int n, k; cin >> n >> k;
        if (n == 0 and k == 0) break;
        vector<int> h(n);
        vector<int> s(n);
        REP (i, n) cin >> h[i];
        REP (i, n) cin >> s[i];
        vector<int> parent(n);
        parent[0] = -1;
        REP3 (i, 1, n) {
            cin >> parent[i];
            -- parent[i];
        }
        vector<int> l(n);
        l[0] = -1;
        REP3 (i, 1, n) cin >> l[i];

        // solve
        vector<vector<int> > children(n);
        REP3 (i, 1, n) {
            children[parent[i]].push_back(i);
        }
        REP (i, n) {
            sort(ALL(children[i]), [&](int i, int j) { return l[i] < l[j]; });
        }

        function<void (int, vector<ll> &)> go = [&](int i, vector<ll> & dp0) {
            vector<ll> dp1 = dp0;
            int h_prev = 0;

            REP (edge, children[i].size() + 1) {
                int j = (edge < children[i].size() ? children[i][edge] : -1);
                int cnt = min(k, j == -1 ? h[i] : l[j]) - h_prev;

                // update
                sliding_window<ll, greater<ll> > window;
                REP (x, k + 1) {
                    window.push_back(x, dp1[x] - (ll) s[i] * x);
                    chmax(dp0[x], window.front() + (ll) s[i] * x);
                    if (x - cnt >= 0) {
                        window.pop_front(x - cnt);
                    }
                }
                if (j == -1) break;

                // shift
                REP3R (x, cnt, k + 1) {
                    dp1[x] = dp1[x - cnt] + (ll) s[i] * cnt;
                }
                REP (x, cnt) {
                    dp1[x] = - INF;
                }
                h_prev += cnt;
                if (h_prev < l[j]) break;

                // recur
                go(j, dp1);
            }

            REP (x, k) {
                chmax(dp0[x + 1], dp0[x]);
            }
            return dp0;
        };

        constexpr int root = 0;
        vector<ll> dp(k + 1, - INF);
        dp[0] = 0;
        go(root, dp);

        // output
        cout << dp[k] << endl;
    }
    return 0;
}
```
