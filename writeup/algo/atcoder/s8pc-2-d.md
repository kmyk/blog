---
layout: post
redirect_from:
  - /blog/2016/04/23/s8pc-2-d/
date: 2016-04-23T23:02:34+09:00
tags: [ "competitive", "writeup", "atcoder", "s8pc" ]
"target_url": [ "https://beta.atcoder.jp/contests/s8pc-2/tasks/s8pc_2_d" ]
---

# square869120Contest #2 D - 2016

## solution

枝刈り全探索。

正整数$n$は$n = 2^{a_0} 3^{a_1} 5^{a_2} 7^{a_3} \dots$という形で一意に表せる。
このような数列$a$で整数を表わす。
このとき約数の個数は$\Pi_i (a_i + 1)$である。

このような数列の上で探索を行なう。
総和$\Sigma a_i$は高々$\log n$程度である。
また、数列$a$が広義単調減少でない場合は無視してよい。
これらから探索空間はそう広くなく、単純に探索すればよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
const int primes[] = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59};
ll factors(vector<int> const & xs) {
    ll y = 1;
    for (int x : xs) y *= 1 + x;
    return y;
}
template <typename R>
R product(vector<int> const & xs) {
    R y = 1;
    repeat (i, xs.size()) repeat (j, xs[i]) y *= primes[i];
    return y;
}
const ll N_MAX = 100000000000000000ll;
int main() {
    map<ll,ll> memo;
    set<vector<int> > used;
    queue<vector<int> > que;
    que.push(vector<int>());
    while (not que.empty()) {
        vector<int> xs = que.front(); que.pop();
        ll k = factors(xs);
        double vr = product<double>(xs);
        if (N_MAX < vr) continue;
        ll vi = product<ll>(xs);
        if (not memo.count(k) or vi < memo[k]) {
            memo[k] = vi;
        }
        int l = xs.size();
        repeat (i,l+1) {
            if (i < l) {
                xs[i] += 1;
            } else {
                xs.push_back(1);
            }
            if (i == 0 or xs[i-1] >= xs[i]) {
                if (not used.count(xs)) {
                    used.insert(xs);
                    que.push(xs);
                }
            }
            xs[i] -= 1;
        }
    }
    int q; cin >> q;
    while (q --) {
        ll n; cin >> n;
        pair<ll,ll> ans = { 0, 0 };
        for (auto p : memo) {
            if (p.second <= n) ans = p;
        }
        cout << ans.first << ' ' << ans.second << endl;
    }
    return 0;
}
```
