---
layout: post
redirect_from:
  - /blog/2018/01/01/code-festival-2017-qualc-d/
date: "2018-01-01T12:14:06+09:00"
tags: [ "competitive", "writeup", "codefestival", "palindrome", "dp", "cumulative-sum" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-qualc/tasks/code_festival_2017_qualc_d" ]
---

# CODE FESTIVAL 2017 qual C: D - Yet Another Palindrome Partitioning

本番も解いたはずなのに見返してしばらく悩んでしまった。
本番では解くの遅くて順位低すぎて精神へのダメージがとても大きかった記憶がある。

## solution

入力例$4$からも分かるように貪欲は嘘。DP。累積和を上手く使って加速。文字種$L = 26$を使って$O(NL)$。

$i$文字目までを回文に分割するときの最小値を$\mathrm{dp}(i)$とする。
区間$[l, r)$中に奇数回出現する文字種の集合を$f(l, r) \subseteq L$とすると、愚直な遷移は$\mathrm{dp}( r) = \min \\{ \mathrm{dp}(l) + 1 \mid l \lt r, \|f(l, r)\| \le 1 \\}$。
$O(N^2)$は間に合わないので加速したい。
$f(l, r)$を累積和$a\_r$としてbitで表現し$f(0, r) \cong a\_r \lt 2^L$とすれば、$l$として見るべきは$a\_l = a\_r \oplus c$ (ただし$\mathrm{popcount}( c) \le 1$)な$l$だけで十分。
長さ$2^L$の表を適当に作ってこれに対するDPのように直せば$O(NL)$となる。

## implementation

``` c++
#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

constexpr int inf = 1e9+7;
int main() {
    string s; cin >> s;
    int n = s.length();
    vector<int> acc(n + 1);
    repeat (i, n) {
        acc[i + 1] = acc[i] ^ (1 << (s[i] - 'a'));
    }
    unordered_map<int, vector<int> > f;
    vector<int> dp(n + 1, inf);
    dp[0] = 0;
    repeat (r, n) {
        f[acc[r]].push_back(r);
        repeat (c, 27) {
            int k = acc[r + 1] ^ (c == 26 ? 0 : (1 << c));
            if (f.count(k)) {
                auto & ls = f[k];
                repeat (i, min<int>(ls.size(), 300)) {
                    int l = ls[i];
                    setmin(dp[r + 1], dp[l] + 1);
                }
                if (ls.size() > 300) {
                    repeat_from (i, ls.size() - 300, ls.size()) {
                        int l = ls[i];
                        setmin(dp[r + 1], dp[l] + 1);
                    }
                }
            }
        }
    }
    cout << dp[n] << endl;
    return 0;
}
```
