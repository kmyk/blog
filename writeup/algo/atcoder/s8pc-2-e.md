---
layout: post
redirect_from:
  - /blog/2016/04/23/s8pc-2-e/
date: 2016-04-23T23:02:37+09:00
tags: [ "competitive", "writeup", "atcoder", "s8pc", "suffix-array", "longest-common-prefix" ]
"target_url": [ "https://beta.atcoder.jp/contests/s8pc-2/tasks/s8pc_2_e" ]
---

# square869120Contest #2 E - 部分文字列

LCPの例題として良さそう。

## solution

suffix array + longest common prefix.

suffix array と longest common prefix の性質からそのまま、いい感じに解ける。
蟻本を読もう。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
vector<int> suffix_array(string const & s) {
    int n = s.length();
    vector<int> sa(n+1);
    vector<int> rank(n+1);
    repeat (i,n+1) {
        sa[i] = i;
        rank[i] = i < n ? s[i] : -1;
    }
    auto rankf = [&](int i) { return i <= n ? rank[i] : -1; };
    vector<int> nxt(n+1);
    for (int k = 1; k <= n; k <<= 1) {
        auto cmp = [&](int i, int j) { return make_pair(rank[i], rankf(i + k)) < make_pair(rank[j], rankf(j + k)); };
        sort(sa.begin(), sa.end(), cmp);
        nxt[sa[0]] = 0;
        repeat_from (i,1,n+1) {
            nxt[sa[i]] = nxt[sa[i-1]] + (cmp(sa[i-1], sa[i]) ? 1 : 0);
        }
        rank.swap(nxt);
    }
    return sa;
}
vector<int> longest_common_prefix_array(string const & s, vector<int> const & sa) {
    int n = s.length();
    vector<int> rank(n+1);
    repeat (i,n+1) rank[sa[i]] = i;
    vector<int> lcp(n);
    int h = 0;
    lcp[0] = 0;
    repeat (i,n) {
        int j = sa[rank[i] - 1];
        if (h > 0) -- h;
        while (j + h < n and i + h < n and s[j + h] == s[i + h]) ++ h;
        lcp[rank[i] - 1] = h;
    }
    return lcp;
}
int main() {
    string s; cin >> s;
    vector<int> sa = suffix_array(s);
    vector<int> lcp = longest_common_prefix_array(s, sa);
    int l = s.size();
    ll ans = 0;
    repeat (i,s.size()+1) if (i) {
        ll t = l - sa[i] - lcp[i-1];
        ans += t * (t + 1) / 2 + lcp[i-1] * t;
    }
    cout << ans << endl;
    return 0;
}
```
