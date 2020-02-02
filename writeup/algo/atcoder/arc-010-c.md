---
layout: post
alias: "/blog/2015/11/03/arc-010-c/"
title: "AtCoder Regular Contest 010 C - 積み上げパズル"
date: 2015-11-03T01:45:52+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dp" ]
---

dpは分かると楽しい。

<!-- more -->

## [C - 積み上げパズル](https://beta.atcoder.jp/contests/arc010/tasks/arc010_3) {#c}

### 問題

色の付いたブロックの列が与えられる。
前から順に使う/使わないを決めていく。
以下のルールに従って得点が得られるので、得られる最大値を答えよ。

-   ブロックを使うとその色に応じた得点が得られる。
-   直前に使ったものと同じブロックを使うと追加で得点。ひとつのブロックで得られる追加の得点は、その時点でのコンボ数に関わらず固定。
-   最終的に、全ての色を使っていたなら得点。


### 解法

dpする。$O(nm2^m)$。

`dp[石を何番目まで見たか][最後に使ったブロックの色][これまでに使った色の集合] = 得点`という形。

### 実装

`result`の初期値を`- inf`にして、ひとつもブロックを使わない場合を無視してしまって、A生やした。

``` c++
#include <iostream>
#include <vector>
#include <map>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
constexpr ll inf = 1000000007;
int main() {
    int n, m, y, z; cin >> n >> m >> y >> z;
    vector<char> c(m);
    vector<int> p(m);
    repeat (i,m) cin >> c[i] >> p[i];
    string b; cin >> b;
    map<char,int> rc; repeat (i,m) rc[c[i]] = i;
    vector<vector<ll> > cur(m, vector<ll>(1 << m, - inf));
    vector<vector<ll> > prv(m, vector<ll>(1 << m, - inf));
    repeat (i,n) {
        int ci = rc[b[i]];
        prv = cur;
        { auto & it = cur[ci][1 << ci]; it = max<ll>(it, p[ci]); }
        repeat (j, m) {
            repeat (k, 1 << m) {
                if (prv[j][k] == - inf) continue;
                auto & it = cur[ci][k | (1 << ci)];
                it = max(it, prv[j][k] + p[ci] + (ci == j ? y : 0));
            }
        }
    }
    ll result = 0;
    repeat (j, m) {
        repeat (k, 1 << m) {
            result = max(result, cur[j][k] + (k == (1<<m)-1 ? z : 0));
        }
    }
    cout << result << endl;
    return 0;
}
```
