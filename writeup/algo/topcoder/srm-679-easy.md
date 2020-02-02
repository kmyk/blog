---
layout: post
alias: "/blog/2016/01/20/srm-679-easy/"
title: "TopCoder SRM 679 div1 Easy: FiringEmployees"
date: 2016-01-20T23:42:10+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "tree", "dp", "greedy" ]
---

## [FiringEmployees]()

### 解説

貪欲。葉の側から順に、解雇するかしないかを決めていけばよい。

### 実装

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
class FiringEmployees { public: int fire(vector<int> manager, vector<int> salary, vector<int> productivity); };

int FiringEmployees::fire(vector<int> manager, vector<int> salary, vector<int> productivity) {
    manager.insert(manager.begin(), -1);
    salary.insert(salary.begin(), 0);
    productivity.insert(productivity.begin(), 0);
    int n = manager.size();
    vector<vector<int> > subordinates(n);
    repeat_from (i,1,n) subordinates[manager[i]].push_back(i);
    vector<int> dp(n);
    repeat_reverse (i,n) {
        dp[i] = productivity[i] - salary[i]; // profit
        for (int j : subordinates[i]) {
            dp[i] += dp[j];
        }
        if (dp[i] < 0) dp[i] = 0; // fire
    }
    return dp[0];
}
```
