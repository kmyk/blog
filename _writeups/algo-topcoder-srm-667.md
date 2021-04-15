---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-667/
  - /blog/2015/09/12/srm-667/
date: 2015-09-12T02:44:18+09:00
tags: [ "topcoder", "srm", "competitive", "writeup" ]
"target_url": [ "http://community.topcoder.com/stat?c=round_overview&er=5&rd=16547" ]
---

# TopCoder SRM 667 Div1 Easy: OrderOfOperations

貪欲で提出してWA貰い零完。黄色防衛ならず(1552 -> 1489)。
貪欲の反例に気付かなかったことと、$m \le 20$の指数では間に合わない気がしてたが全然そんなことなかったことが敗因。

<!-- more -->

## [Easy: OrderOfOperations](http://community.topcoder.com/stat?c=problem_statement&pm=13987&rd=16547) {#easy}

### 問題

ある$m \le 20$に対し$m$桁のbit列が$n \le 50$本与えられる。
上から1本ずつ順に見ていき今までに立ったことがなくて今回初めて立つbitの数の2乗を計算しその総和を取る。
適当に並べ変えたときのその最小値を求める。

### 解法/解答

bitは高々20桁なのでbitに関して全部試せる($2^{20} \approx 10^6$)。bit DPやDijkstra法で通る。
既に使用したbit列をもう一度使用してもコストは0なので、何度でも使用できることに注意。

立っているbit数の少ない順に取る貪欲解の反例としては以下。真ん中の`"00111"`から取るのが正解。

``` plain
s: {"11000",
    "00111",
    "10111"}
```

#### bit DP

$O(2^mn)$

``` c++
#include <bits/stdc++.h>
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define repeat(i,n) repeat_from (i,0,n)
using namespace std;
class OrderOfOperations {
    public:
    int minTime(vector<string> s) {
        int n = s.size();
        int m = s.back().size();
        vector<int> bit(n);
        repeat (i,n) repeat (j,m) if (s[i][j] == '1') bit[i] |= 1 << j;
        constexpr int INF = 1<<28;
        vector<int> dp(1 << m, INF);
        dp[0] = 0;
        repeat (u, 1<<m) {
            if (dp[u] == INF) continue;
            repeat (j,n) {
                int newbit = bit[j] & ~u;
                if (newbit != 0) {
                    int p = __builtin_popcount(newbit);
                    dp[u | newbit] = min(dp[u | newbit], dp[u] + p*p);
                }
            }
        }
        int u = accumulate(bit.begin(), bit.end(), 0, bit_or<int>());
        return dp[u];
    }
};
```

#### Dijkstra法

$O(E + V\log V)$で$V = 2^m$, $E = 2^mn$なので$O(2^m(n + m))$

``` c++
#include <bits/stdc++.h>
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define repeat(i,n) repeat_from (i,0,n)
using namespace std;
template <class T>
using reversed_priority_queue = std::priority_queue<T, std::vector<T>, std::greater<T> >;
struct state_t {
    int bit; int cost;
};
bool operator > (state_t const & a, state_t const & b) {
    return a.cost > b.cost;
}
class OrderOfOperations {
    public:
    int minTime(vector<string> s) {
        int n = s.size();
        int m = s.back().size();
        vector<int> bit(n);
        repeat (i,n) repeat (j,m) if (s[i][j] == '1') bit[i] |= 1 << j;
        int last = accumulate(bit.begin(), bit.end(), 0, bit_or<int>());
        reversed_priority_queue<state_t> q;
        q.push((state_t){ 0, 0 });
        vector<bool> used(1<<m);
        while (not q.empty()) {
            state_t t = q.top(); q.pop();
            if (used[t.bit]) continue;
            if (t.bit == last) return t.cost;
            used[t.bit] = true;
            repeat (i,n) {
                int newbit = bit[i] & ~t.bit;
                if (used[t.bit | newbit]) continue;
                int p = __builtin_popcount(newbit);
                q.push((state_t){ t.bit | newbit, t.cost + p*p });
            }
        }
        return -1;
    }
};
```

<hr>

DP苦手なので、DPのやつは診断人さんの放送見ながらantaさんの解答を多いに参考にして書いてた。

Medは手も足も出ず。
