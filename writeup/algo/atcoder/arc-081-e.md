---
layout: post
alias: "/blog/2017/08/21/arc-081-e/"
date: "2017-08-21T00:12:17+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc081/tasks/arc081_c" ]
---

# AtCoder Regular Contest 081: E - Don't Be a Subsequence

解けたけど遅かったので提出せず。
もう既に橙からは落ちているのでわざわざ下げる行為はしなくていいやという気持ちがあった。

## solution

DP。$O(N)$。

まず辞書順最小制約を緩和して長さだけ考える。
先頭から始めて、その位置から見て最も後ろに出現する文字を選んでそこまで飛ぶ、これを繰り返す貪欲っぽい方法で求まる。
後ろから適当な表を持ちつつ見て経路復元すればこれは$O(N)$。

この操作を拡大する。
それぞれの位置についてその位置でまず文字$c$で飛んでそれ以降は最短で移動したときの移動回数を計算する。これはほとんど同様にできる。経路復元を適当に修正すれば辞書順最小にできる。

## implementation

``` c++
#include <array>
#include <iostream>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(x) begin(x), end(x)
using namespace std;

constexpr int inf = 1e9+7;
int main() {
    string s; cin >> s;
    int n = s.length();
    vector<int> dp(n + 2, inf);
    dp[n + 1] = 0;
    dp[n] = 1;
    vector<pair<char, int> > g(n + 1);
    g[n] = { 'a', n + 1 };
    array<int, 26> f;
    fill(whole(f), n + 1);
    repeat_reverse (i, n) {
        f[s[i] - 'a'] = i + 1;
        repeat (j, 26) {
            if (1 + dp[f[j]] < dp[i]) {
                dp[i] =  1 + dp[f[j]];
                g[i] = { 'a' + j, f[j] };
            }
        }
    }
    string t;
    for (int i = 0; i < n + 1; ) {
        char c; tie(c, i) = g[i];
        t += c;
    }
    cout << t << endl;
    return 0;
}
```
