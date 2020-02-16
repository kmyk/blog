---
layout: post
alias: "/blog/2016/01/31/hackerrank-worldcodesprint-print-string/"
date: 2016-01-31T01:43:38+09:00
tags: [ "competitive", "writeup", "hackerrank", "dp", "suffix-array", "world-codesprint" ]
---

# HackerRank World Codesprint: Build a String

## [Build a String](https://www.hackerrank.com/contests/worldcodesprint/challenges/print-string)

### 問題

空列$\epsilon$に対し以下の操作を繰り返し、文字列$S$を作りたい。これにかかる費用の最小値を答えよ。

-   文字列の末尾に好きな$1$文字を加える。$x \mapsto xc$。費用は$A$かかる。
-   現在の文字列の部分文字列を末尾に加える。$xyz \mapsto xyzy$。費用は$B$かかる。

### 解法

DP + suffix array。$O(N^2)$。

$S$は先頭から構成されていく。
$i$文字目まで作るのにかかる費用を${\rm dp}\_i$とする。
${\rm dp}\_{i+1} = \min ( \\{ {\rm dp}\_{i} + A \\} \cup \\{ {\rm dp}\_{i-j} + B \mid 1 \le j \le l \\} )$である。$l$は文字列$S$の部分文字列$[i-l,i)$が$[0,i-l)$中に含まれるような$l$の中で最大のものである。

$l$を求めたい。
$S$を反転した文字列に関するsuffix arrayを作る。
このsuffix array上での$i$で終わる文字列の位置を中心に、上下を見ていく。
$i$より左から始まり、$i$から始まるものと一致しかつ一致する部分が重ならないような部分文字列の長さは、これにより$O(N)$で求まる。

"target_url": [ "small" ]
---

# HackerRank World Codesprint: Build a String
editorialによると${\rm dp}\_i$は単調であるようだ。今回の場合、これを使っても使わなくても計算量は変化しない。
</small>

### 実装

もっとすっきり解けそうな印象。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
pair<vector<int>,vector<int> > suffix_array_and_rank(string const & s) { // O(nloglogn)
    int n = s.length();
    vector<int> sa(n+1);
    vector<int> rank(n+1);
    repeat (i,n+1) {
        sa[i] = i;
        rank[i] = i < n ? s[i] : -1;
    }
    for (int k = 1; k <= n; k *= 2) {
        auto compare = [&](int i, int j) {
            int ri = i + k <= n ? rank[i + k] : -1;
            int rj = j + k <= n ? rank[j + k] : -1;
            return make_pair(rank[i], ri) < make_pair(rank[j], rj);
        };
        sort(sa.begin(), sa.end(), compare);
        vector<int> dp(n+1);
        dp[sa[0]] = 0;
        repeat (i,n) dp[sa[i+1]] = dp[sa[i]] + compare(sa[i], sa[i+1]);
        rank = dp;
    }
    return { sa, rank };
}

int longest_prefix_length(string const & t, vector<int> const & sa, vector<int> const & rank, int offset) {
    int ans = 0;
    for (int i = rank[offset]; i >= 1; -- i) {
        if (t[sa[i]] != t[offset]) break; // means l is 0
        if (sa[i] <= offset) continue;
        int l = mismatch(t.begin() + sa[i], t.end(), t.begin() + offset).second - (t.begin() + offset);
        if (l <= ans) break;
        ans = max(ans, min(sa[i] - offset, l));
    }
    for (int i = rank[offset]; i < sa.size(); ++ i) {
        if (t[sa[i]] != t[offset]) break; // means l is 0
        if (sa[i] <= offset) continue;
        int l = mismatch(t.begin() + sa[i], t.end(), t.begin() + offset).second - (t.begin() + offset);
        if (l <= ans) break;
        ans = max(ans, min(sa[i] - offset, l));
    }
    return ans;
}
void solve() {
    int n, a, b; string s; cin >> n >> a >> b >> s;
    string t(s.rbegin(), s.rend());
    vector<int> sa, rank; tie(sa, rank) = suffix_array_and_rank(t);
    vector<int> dp(n+1); // monotonic
    repeat (i,n) {
        dp[i+1] = dp[i] + a;
        int l = longest_prefix_length(t, sa, rank, n-i-1);
        if (l) repeat (j,l) dp[i+1] = min(dp[i+1], dp[i-j] + b);
    }
    cout << dp[n] << endl;
}
int main() {
    int t; cin >> t;
    repeat (i,t) solve();
    return 0;
}
```
