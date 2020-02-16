---
layout: post
redirect_from:
  - /blog/2016/05/15/arc-053-d/
date: 2016-05-15T04:53:21+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "graph", "path", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc053/tasks/arc053_d" ]
---

# AtCoder Regular Contest 053 D - 2 つの山札

## solution

[editorial](https://beta.atcoder.jp/contests/arc053/data/arc/053/editorial.pdf)

## 感想

-   遷移のグラフまでは考えていた。グリッドグラフや経路という形では認識できていなかった。
    -   綺麗な合流のあるグラフは、グリッドにすることを考えるべきっぽい。軸並行なそれのほうが考えやすい。
    -   それまでの操作全て、を考えるようなものは、経路という形で言い換えられるらしい。
-   状態数が$N \times N$になりそうというのは気付いていた。しかし更新ができなかった。
    -   更新ができない理由は、同じ経路が複数箇所に存在するため単純には足せない、区別が必要であるから。
    -   区別が必要なのなら区別すればよいというわけ。
    -   単純に足せないならそれができるように分ける、は良く見る気がする。
-   私は気合いで実装したが、もっと簡潔な実装での提出が見られる。私の解法への理解が浅いからだろう。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <map>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
const int mod = 1e9+7;
enum state_t {
    only_a,
    only_b,
    both,
};
int main() {
    // input
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) { cin >> a[i]; -- a[i]; } // weight on   vertical edges
    vector<int> b(n); repeat (i,n) { cin >> b[i]; -- b[i]; } // weight on horizontal edges
    // calculate
    vector<vector<vector<ll> > > dp(2*n-2+1, vector<vector<ll> >(n, vector<ll>(3))); // dp[length][last number][last edge]
    if (a[0] == b[0]) {
        dp[1][a[0]][both] = 1; // initial state
    } else {
        dp[1][a[0]][only_a] = 1;
        dp[1][b[0]][only_b] = 1;
    }
    repeat_from (l,2,2*n-2+1) {
        // collect moves
        vector<map<state_t,set<pair<int,state_t> > > > used(n);
        repeat (x,l+1) {
            int y = l-x;
            if (y < 0 or n <= y or x < 0 or n <= x) continue;
            if (y >= 2           ) used[a[x]][only_a].insert(make_pair(a[x  ], only_a));
            if (y >= 1 and x >= 1) used[a[x]][only_a].insert(make_pair(b[y-1], only_b));
            if (           x >= 2) used[b[y]][only_b].insert(make_pair(b[y  ], only_b));
            if (y >= 1 and x >= 1) used[b[y]][only_b].insert(make_pair(a[x-1], only_a));
        }
        // construct values
        repeat (p,n) {
            if (used[p].count(only_a) and used[p].count(only_b)) {
                if (used[p][only_a] == used[p][only_b]) { // after the crossing point
                    set<int> qs;
                    for (auto it : used[p][only_a]) {
                        int q; state_t s; tie(q, s) = it;
                        qs.insert(q);
                        dp[l][p][both] += dp[l-1][q][s];
                    }
                    for (int q : qs) {
                        dp[l][p][both] += dp[l-1][q][both];
                    }
                    continue;
                }
            }
            // regular cases
            vector<set<int> > qss(2); // for both
            repeat (s,2) {
                if (used[p].count(state_t(s))) {
                    for (auto it : used[p][state_t(s)]) {
                        int q; state_t t; tie(q, t) = it;
                        qss[s].insert(q);
                        dp[l][p][s] += dp[l-1][q][t]; // add the only-X-counts
                    }
                }
            }
            for (int q : qss[only_a]) {
                state_t s = only_a;
                if (qss[only_b].count(q)) s = both;
                dp[l][p][s] += dp[l-1][q][both]; // add the both-counts
            }
            for (int q : qss[only_b]) {
                if (qss[only_a].count(q)) continue;
                dp[l][p][only_b] += dp[l-1][q][both];
            }
        }
        repeat (p,n) {
            repeat (s,3) {
                dp[l][p][s] %= mod; // do mod here, to simplify the code
            }
        }
    }
    // output
    ll ans = 0;
    repeat (p,n) repeat (i,3) ans += dp[2*n-2][p][i];
    cout << (ans % mod + mod) % mod << endl;
    return 0;
}
```
