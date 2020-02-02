---
layout: post
alias: "/blog/2018/04/22/2018-tco-algo-r1-medium/"
title: "2018 TCO Algorithm: Medium. Resistance"
date: "2018-04-22T02:57:53+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "tco", "probability" ]
---

## solution

$2^P$通り全て試して間に合う。$O(2^PM)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
class Resistance { public: vector<double> spyProbability(int P, int S, vector<string> missions); };

vector<double> Resistance::spyProbability(int P, int S, vector<string> missions) {
    vector<int> masks;
    for (string const & mission : missions) if (mission[0] == 'F') {
        int acc = 0;
        REP (i, P) if (mission[i + 1] == '1') {
            acc |= 1 << i;
        }
        masks.push_back(acc);
    }
    vector<int> num(P);
    int den = 0;
    REP (spies, 1 << P) {
        if (__builtin_popcount(spies) != S) continue;
        bool valid = true;
        for (int mask : masks) {
            if (not (spies & mask)) {
                valid = false;
                break;
            }
        }
        if (valid) {
            REP (i, P) if (spies & (1 << i)) {
                num[i] += 1;
            }
            den += 1;
        }
    }
    if (den == 0) return vector<double>();
    vector<double> prob(P);
    REP (i, P) prob[i] = num[i] / (double)den;
    return prob;
}
```
