---
layout: post
alias: "/blog/2016/01/30/discovery-2016-qual-b/"
date: 2016-01-30T23:17:12+09:00
tags: [ "competitive", "writeup", "atcoder", "discovery-channel", "greedy", "binary-search" ]
---

# DISCO presents ディスカバリーチャンネル Programming Contest 2016 Qualification B - ディスコ社内ツアー

制約を、各周に関してその周のなかで面白さ$A_i$が広義単調、と誤読してlisを書いていた。これが無ければC通っていた可能性がある。

## [B - ディスコ社内ツアー](https://beta.atcoder.jp/contests/discovery2016-qual/tasks/discovery_2016_qual_b)

### 解法

貪欲 + 二分探索。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    map<int,vector<int> > cnt; // ordered map
    repeat (i,n) cnt[a[i]].push_back(i);
    int ans = 0;
    int x = 0;
    for (auto && it : cnt) {
        vector<int> & xs = it.second;
        sort(xs.begin(), xs.end());
        if (x <= xs.front()) {
            x = xs.back();
        } else {
            auto it = lower_bound(xs.begin(), xs.end(), x);
            x = *(-- it);
            ++ ans;
        }
    }
    if (x != 0) ++ ans;
    cout << ans << endl;
    return 0;
}
```
