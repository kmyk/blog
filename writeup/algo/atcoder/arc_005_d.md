---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-005-d/
  - /blog/2015/09/30/arc-005-d/
date: 2015-09-30T17:17:51+09:00
tags: [ "atcoder", "competitive", "arc", "writeup" ]
---

# AtCoder Regular Contest 005 D - 連射王高橋君

苦戦した。答え見まくった。精進には丁度よい難易度だったように思う。

<!-- more -->

## [D - 連射王高橋君](https://beta.atcoder.jp/contests/arc005/tasks/arc005_4) {#d}

### 問題

`0123456789+=`のボタンを持つ電卓がある。ただし`23456789`のいくつかは壊れていて使えないことが分かっている。ある数を作るのに必要な入力の長さの最小値を求める。

### 解法

`+`の数を固定し、下位の桁から再帰。

`+`の数が固定されると、n桁目の数の総和(例えば`123+45+67+8=`の2桁目なら$2+4+6=12$)で可能なものを列挙できる。
これを使って、目的の数を最下位から作っていく。

例えば1個の`+`と数字`0137`で数`1234`を作るとき、最下位の数の総和として可能なのは$1+3$か$7+7$で、それを引いた残りに関して再帰し、その結果に引いた数を加えて更新し、その中で最小のもの答え。

最下位桁の総和を引いた数を作る最短の列から、元の数を作る最短の列が本当に復元できるのかどうか、ちゃんと証明はしてない。

### 今日のバグ

再帰の基底にてバグ。
空の`vector<ll>`を探索失敗として使いたいが、`price == 0`の時は空のものが返るべきだという問題があった。これを回避するために、`price == 0`が呼び出されないようにしたのが原因。
自然な値域にエラーを表わす値を捩じ込むべきではなかった。

具体的には、目的の数が丁度作れると判明したら、その場でその値をreturnしてしまっていた。
`13`が`5+8=`で作れても、`13`(`3` -> `1` と再帰)の方がよい。

### 解答

``` c++
#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
string format(vector<ll> const & a) {
    ostringstream oss;
    repeat (i, a.size()) {
        if (i) oss << '+';
        oss << a[i];
    }
    if (a.size() >= 2) oss << '=';
    return oss.str();
}
vector<ll> bar(ll price, map<ll,vector<int> > const & s, map<ll,vector<ll> > & memo) {
    if (memo.count(price)) return memo[price];
    if (price == 0) return memo[price] = vector<ll>();
    ll d = price / 10;
    ll m = price % 10;
    vector<ll> result;
    for (auto p : s) {
        ll sd = p.first / 10;
        ll sm = p.first % 10;
        if (sm == m and sd <= d) {
            vector<ll> a = bar(d - sd, s, memo);
            if (not a.empty() or d - sd == 0) {
                int n = p.second.size();
                if (a.size() < n) a.resize(n);
                repeat (i, a.size()) {
                    a[i] = a[i] * 10;
                    if (i < n) a[i] += p.second[i];
                }
                if (result.empty() or format(a).size() < format(result).size()) {
                    result = a;
                }
            }
        }
    }
    return memo[price] = result;
}
string foo(bool const (& b)[10], ll price) {
    map<ll,vector<int> > s; // `s[n] = i` means the number `n` can be made as sum of `s[n]`
    s[0] = vector<int>();
    repeat_from (n,1,9+1) { // use `n` numbers and `n - 1` `+`s
        map<ll,vector<int> > t = s;
        for (auto p : t) {
            repeat (i,10) if (b[i]) {
                if (not s.count(p.first + i)) {
                    s[p.first + i] = p.second;
                    s[p.first + i].push_back(i);
                }
            }
        }
        map<ll,vector<ll> > memo;
        vector<ll> result = bar(price, s, memo);
        if (not result.empty()) return format(result);
    }
    assert (false);
}
int main() {
    bool b[10] = {}; {
        string s; cin >> s;
        for (char c : s) b[c - '0'] = true;
    }
    ll price; cin >> price;
    cout << foo(b, price) << endl;
    return 0;
}
```

生成器

``` python
#!/usr/bin/env python3
import random
b = [0,1]
for i in range(2,9+1):
    if random.choice([True, False]):
        b.append(i)
print(''.join(map(str,b)))
print(random.randint(1, 10**18))
```


自動提出script導入して誤爆しまくってた
