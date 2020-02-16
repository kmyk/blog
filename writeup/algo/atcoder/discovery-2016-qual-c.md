---
layout: post
alias: "/blog/2016/01/30/discovery-2016-qual-c/"
date: 2016-01-30T23:17:28+09:00
tags: [ "competitive", "writeup", "discovery-channel", "atcoder", "suffix-array" ]
---

# DISCO presents ディスカバリーチャンネル Programming Contest 2016 Qualification C - アメージングな文字列は、きみが作る！

通せず。通せていればonsite獲得だったようであるし通せてもおかしくない問題だったのでけっこうくやしい。

## [C - アメージングな文字列は、きみが作る！](https://beta.atcoder.jp/contests/discovery2016-qual/tasks/discovery_2016_qual_c)

### 解法

丁寧にやる。

基本的には先頭に文字`a`を追加しまくればよい。
ただし、削除によって文字`a`のみからなる文字列を作れるならそうすべきである。
また、文字列の先頭に`a`を追加するのでなくて、先頭の連続する`a`に後続する文字列の先頭を`a`に置き換えるほうが有利な場合もある。
これらを丁寧に処理すればよい。

特に後者に関して、先頭に追加する`a`の数$a$と置き換えあるいは元々含まれていた`a`の数$b$を持ちながら前から舐めればよい。
また、`s.substr(i) < s.substr(j)`を高速に実行するためにsuffix arrayを使う必要がある。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
vector<int> suffix_rank(string const & s) { // O(nloglogn)
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
    return rank;
}

int main() {
    string s; int k; cin >> s >> k;
    int n = s.size();
    if (n - count(s.begin(), s.end(), 'a') <= k) {
        cout << string(n-k, 'a') << endl;
    } else {
        vector<int> rank = suffix_rank(s);
        int a = k, b = 0;
        int x = k, y = 0;
        repeat (i,n) {
            if (s[i] == 'a') {
                ++ b;
            } else {
                -- a;
                ++ b;
                if (a < 0) break;
            }
            if (x < a+b) {
                x = a+b;
                y = i+1;
            } else if (x == a+b and rank[i+1] < rank[y]) {
                y = i+1;
            }
        }
        cout << string(x, 'a') << s.substr(y) << endl;
    }
    return 0;
}
```
