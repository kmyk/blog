---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-012-e/
  - /blog/2017/06/14/agc-012-e/
date: "2017-06-14T22:24:02+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc012/tasks/agc012_e" ]
---

# AtCoder Grand Contest 012: E - Camel and Oases

## solution

ジャンプできるのは$k \approx \log V$回。
$i$回目のジャンプのあとに相互に移動できるオアシスの区間をそれぞれ求めておく。
何回目のジャンプを使ったかの集合$s \in \mathcal{P}(k)$からそれで(左端/右端から)どこまでいけるかの関数$r, l : \mathcal{P}(k) \to N+1$を計算する。
部分集合を全部試しても$2^k \approx 2^{\log V} = V$で間に合う。
初期位置が指定されたときはその連結成分を始めに使うことになるので、初期位置から到達できるオアシスの区間$[l, r]$に対しある集合$s \subseteq \mathcal{P}(k-1)$で$l \le r(s) \land l(\mathcal{P}(k-1) \setminus s) \le r$なものが存在するかどうか見ればよい。
$O(N \log V + V (\log V)^2)$。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <tuple>
#include <cassert>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

template <typename UnaryPredicate>
ll binsearch(ll l, ll r, UnaryPredicate p) { // [l, r), p is monotone
    assert (l < r);
    -- l;
    while (r - l > 1) {
        ll m = (l + r) / 2;
        (p(m) ? r : l) = m;
    }
    return r; // = min { x | p(x) }
}

int main() {
    int n, v; scanf("%d%d", &n, &v);
    vector<int> x(n); repeat (i, n) scanf("%d", &x[i]);

    vector<int> vs;
    for (int cur_v = v; cur_v > 0; cur_v /= 2) vs.push_back(cur_v);
    vs.push_back(0);
    whole(reverse, vs);
    int k = vs.size();

    vector<vector<pair<int, int> > > range(k); // [l, r]
    repeat (l, n) {
        range[0].emplace_back(l, l);
    }
    repeat (i, k-1) {
        int v = vs[i+1]; // shadowing
        for (int j = 0; j < range[i].size(); ) {
            int l1, r1; tie(l1, r1) = range[i][j];
            ++ j;
            while (j < range[i].size()) {
                int l2, r2; tie(l2, r2) = range[i][j];
                assert (r1 + 1 == l2);
                if (x[l2] - x[r1] <= v) {
                    r1 = r2;
                    ++ j;
                } else {
                    break;
                }
            }
            range[i+1].emplace_back(l1, r1);
        }
    }

    vector<int> dp_l(1 << (k-1)); // [0, r)
    vector<int> dp_r(1 << (k-1), n-1); // (l, n-1]
    repeat (s, 1 << (k-1)) {
        repeat (i, k-1) if (not (s & (1 << i))) {
            int t = s | (1 << i);
            int jr = binsearch(0, range[i].size(), [&](ll j) {
                int l, r; tie(l, r) = range[i][j];
                return dp_l[s] < l;
            }) - 1;
            int jl = binsearch(0, range[i].size(), [&](ll j) {
                int l, r; tie(l, r) = range[i][j];
                return dp_r[s] <= r;
            });
            setmax(dp_l[t], jr < range[i].size() ? range[i][jr].second + 1 :  n);
            setmin(dp_r[t], jl < range[i].size() ? range[i][jl].first  - 1 : -1);
        }
    }

    for (auto it : range[k-1]) {
        int l, r; tie(l, r) = it;
        bool possible = false;
        repeat (s, 1 << (k-1)) {
            int t = ((1 << (k-1)) - 1) & ~ s;
            if (l <= dp_l[s] and dp_r[t] <= r) {
                possible = true;
                break;
            }
        }
        repeat (i, r - l + 1) {
            printf("%s\n", possible ? "Possible" : "Impossible");
        }
    }
    return 0;
}
```
