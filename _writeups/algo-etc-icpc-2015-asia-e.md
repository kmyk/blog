---
layout: post
redirect_from:
  - /writeup/algo/etc/icpc-2015-asia-e/
  - /blog/2015/12/03/icpc-2015-asia-e/
date: 2015-12-03T02:33:19+09:00
tags: [ "competitive", "writeup", "icpc", "aoj", "dp" ]
---

# ACM ICPC 2015 アジア地区予選 E : Bringing Order to Disorder

本番はちょっと見たけど、分からなさそうなので飛ばした。
私の苦手な問題だったように見える。

本番終了後に人に解法を聞くと皆 半分全列挙と答えるものの、具体的にどう半分にするのかよく分からなかった。参加記巡りをしていたら桁DPという文字列が見え、すぐに解法が分かった。
本番の私は桁DPは一切思い浮かべなかったが、時間があって3人で考えていたら桁DPという単語は出ていただろうし、解けていたと思う。

<!-- more -->

## [E : Bringing Order to Disorder](http://judge.u-aizu.ac.jp/onlinejudge/cdescription.jsp?cid=ICPCOOC2015&pid=E) {#e}

### 問題

数字のみからなる長さ$n$の文字列$s$に、$({\rm sum}(s), {\rm prod}(s), {\rm int}(s))$の辞書式順序による比較で定義される順序を導入する。
ただし、${\rm sum}(s) = \Sigma\_{c \in s} c$、${\rm prod}(s) = \Pi\_{c \in s} (c+1)$、${\rm int}(s) = ({\rm sを整数として解釈したもの})$、である。

数字のみからなる長さ$n$の文字列$s$が与えられる。文字列$s$は長さ$n$の文字列の中で、上の順序で数えて何番目か。

### 解法

sumとprodに関してdpし、次にintに関してdp。

まずintを無視して、文字列$t$で、明らかに$s$より小さいものの数を数える。
つまり、${\rm sum}(t) \lt {\rm sum}(s)$あるいは${\rm sum}(t) = {\rm sum}(s) \land {\rm prod}(t) \lt {\rm prod}(s)$なものの数を数える。
`dp[何文字目][総和][総乗] = 種類`の形のdp。
${\rm prod}(s)$として現れる数の種類はそう多くないため、連想配列で持ってしまえばよい。

次に、$s$と同じsumとprodを持つもの中での$s$の順位を定める。
つまり、${\rm sum}(t) = {\rm sum}(s) \land {\rm prod}(t) = {\rm prod}(s) \land {\rm int}(t) \le {\rm int}(s)$なものの数を数える。
これは`dp[何文字目][ここまでがsと一致しているか][総和][総乗] = 種類`というdp。
基本的に先程のdpと同じであるが、$s$より大きくなるようなものは数えない。

### 反省

-   この問題見て桁DPが出てこないの、冷静に考えて経験が足りなさすぎる

### 実装

``` c++
#include <iostream>
#include <vector>
#include <unordered_map>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    string s; cin >> s;
    int sum = accumulate(s.begin(), s.end(), 0) - '0' * s.length();
    ll prod = 1; for (char c : s) prod *= c + 1 - '0';
    ll acc = 0;
    { // decide for sum and prod
        vector<vector<unordered_map<ll,ll> > > dp(s.length()+1,
               vector<unordered_map<ll,ll> >(sum+1));
        dp[0][0][1] = 1;
        repeat (i,s.length()) {
            repeat (j,sum+1) {
                for (auto it : dp[i][j]) {
                    ll k = it.first;
                    repeat (d,10) {
                        if (j+d < sum or (j+d == sum and k*(d+1) < prod)) {
                            dp[i+1][j+d][k*(d+1)] += dp[i][j][k];
                        }
                    }
                }
            }
        }
        repeat (j,sum+1) {
            for (auto it : dp[s.length()][j]) {
                acc += it.second;
            }
        }
    }
    { // decide for int
        array<vector<vector<unordered_map<ll,ll> > >,2> dp;
        dp[0].resize(s.length()+1, vector<unordered_map<ll,ll> >(sum+1));
        dp[1].resize(s.length()+1, vector<unordered_map<ll,ll> >(sum+1));
        dp[0][0][0][1] = 1;
        repeat (l,2) { // 0 : match, 1 : not
            repeat (i,s.length()) {
                repeat (j,sum+1) {
                    for (auto it : dp[l][i][j]) {
                        ll k = it.first;
                        repeat (d,10) {
                            int nl = 1;
                            if (l == 0 and d >  s[i]-'0') continue;
                            if (l == 0 and d == s[i]-'0') nl = 0;
                            if (j+d >  sum) continue;
                            if (j+d == sum) {
                                if (prod % (k*(d+1)) != 0) continue;
                                if (k*(d+1) >  prod) continue;
                            }
                            dp[nl][i+1][j+d][k*(d+1)] += dp[l][i][j][k];
                        }
                    }
                }
            }
        }
        acc += dp[0][s.length()][sum][prod];
        acc += dp[1][s.length()][sum][prod] - 1;
    }
    cout << acc << endl;
    return 0;
}
```
