---
layout: post
alias: "/blog/2016/12/17/dwacon2017-prelims-b/"
date: "2016-12-17T22:04:43+09:00"
title: "第3回 ドワンゴからの挑戦状 予選: B - ニコニコレベル"
tags: [ "competitive", "writeup", "atcoder", "dwacon", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2017-prelims/tasks/dwango2017qual_b" ]
---

Eが解けないのでこの問題もgolfしようとしたのだが、雑に書いて提出したらWAったのでなかったことになった。

## solution

適当にDP。$O(N)$。

偶奇で分ける、つまり`252525...`と`525252...`を用意してmaskにすると楽かも。
正規表現などでもできそうだが、連続する`?`をひとつ使わず見送るべき場合があるので単純ではない(が、できるようだ: <https://beta.atcoder.jp/contests/dwacon2017-prelims/submissions/1030259>)。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
int main() {
    string s; cin >> s;
    int n = s.length();
    int ans = 0;
    vector<array<int, 2> > dp(n+1);
    dp[0][0] = 0;
    dp[0][1] = -1;
    repeat (i,n) {
        dp[i+1][0] = 0;
        dp[i+1][1] = -1;
        if (s[i] == '2' or s[i] == '?') {
            dp[i+1][1] = dp[i][0] + 1;
        }
        if (s[i] == '5' or s[i] == '?') {
            if (dp[i][1] != -1) dp[i+1][0] = dp[i][1] + 1;
        }
        setmax(ans, dp[i+1][0]);
    }
    cout << ans << endl;
    return 0;
}
```
