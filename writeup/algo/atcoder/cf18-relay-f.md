---
layout: post
date: 2018-11-21T11:15:35+09:00
tags: [ "competitive", "writeup", "atcoder", "code-festival", "dp", "expected-value", "imos-method" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf18-relay-open/tasks/relay2018_f" ]
---

# Code Festival (2018) Team Relay: F - バス旅行

## 解法

### 概要

DP。とりあえず$$O(Nk^2)$$を書いて適当にすると$$O(Nk)$$に落ちる。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

double solve(int n, int k, vector<int> const & t) {
    double acc = 0;
    vector<double> cur(k), prv;
    cur[0] = 1;
    REP (i, n) {
        cur.swap(prv);
        cur.assign(k, 0);

/*
        // O(k^2)
        REP (arrive, k) {
            REP3 (depart, arrive, k) {
                int wait = depart - arrive;
                double p = prv[arrive] * (1.0 / k);
                acc += p * wait;
                cur[(depart + t[i]) % k] += p;
            }
            REP (depart, k) {
                int wait = k + depart - arrive;
                double p = prv[arrive] * ((double)arrive / k) * (1.0 / k);
                acc += p * wait;
                cur[(depart + t[i]) % k] += p;
            }
        }
*/

        // O(k)
        REP (arrive, k) {  // arrive <= depart
            double p = prv[arrive] * (1.0 / k);
            double sum_wait = (k - arrive) * ((arrive + k - 1) / 2.0 - arrive);
            acc += p * sum_wait;
            if (arrive + t[i] % k < k) {
                cur[0] += p;
                cur[arrive + t[i] % k] += p;
            } else {
                cur[(arrive + t[i]) % k] += p;
            }
            cur[t[i] % k] -= p;
        }
        REP (j, k - 1) {
            cur[j + 1] += cur[j];  // imos's method
        }
        double prob = 0;
        REP (arrive, k) {  // depart < arrive
            double average_wait = k + ((k - 1) / 2.0) - arrive;
            double p = prv[arrive] * ((double)arrive / k) * (1.0 / k);
            acc += p * average_wait * k;
            prob += p;
        }
        REP (depart, k) {
            cur[depart] += prob;
        }

    }
    return accumulate(ALL(t), 0ll) + acc;
}

int main() {
    int n, k; cin >> n >> k;
    vector<int> t(n);
    REP (i, n) cin >> t[i];
    cout << setprecision(16) << solve(n, k, t) << endl;
    return 0;
}
```
