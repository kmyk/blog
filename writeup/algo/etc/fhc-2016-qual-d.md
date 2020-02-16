---
layout: post
alias: "/blog/2016/01/11/fhc-2016-qual-d/"
date: 2016-01-12 9:00:00 +0900
tags: [ "competitive", "writeup", "facebook-hacker-cup", "trie", "graph", "dp" ]
---

# Facebook Hacker Cup 2016 Qualification Round Text Editor

かなり好きな問題。

## [Text Editor](https://www.facebook.com/hackercup/problem/1525154397757404/)

### 問題

単語が$N$個($N \le 300$)与えられる。単語の長さの総和$L$は$100000$以下である。
この中から$K$個好きに選んで出力するとき、必要な打鍵数の最小を答えよ。
ただしキーには、`a`から`z`までの文字、一文字消す、出力をする、がある。
また終了時には全ての文字を消しておかなければならない。

### 解法

与えられた単語からtrie木を作ると、木が与えられ指定された頂点$N$個から$K$選んで巡る問題と見ることができる。
後はdpをすればよい。
各部分木に関して、指定された頂点を$k$個巡るときの長さを全て求めれば、全体に関して同じものが求まる。
$O(LN)$。

### 実装

忘れても問題はないが、`free`や`delete`は忘れずしておくべき。

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
struct trie_t { trie_t *p[26]; bool exists; int count; };
trie_t *new_trie() {
    trie_t *t = new trie_t;
    repeat (i,26) t->p[i] = NULL;
    t->exists = false;
    t->count = 0;
    return t;
}
trie_t *get_valid_trie(trie_t *t, char c) {
    if (not t->p[c-'a']) t->p[c-'a'] = new_trie();
    return t->p[c-'a'];
}
void delete_trie(trie_t *t) {
    repeat (i,26) if (t->p[i]) delete_trie(t->p[i]);
    delete t;
}
vector<int> bar(trie_t *t) {
    vector<int> dp(t->count + 1, 1000000007);
    dp[0] = 0;
    if (t->exists) dp[1] = 1;
    repeat (i,26) if (t->p[i]) {
        vector<int> a = bar(t->p[i]);
        repeat_reverse (j,dp.size()) {
            repeat (k,a.size()) if (0 <= j-k) {
                dp[j] = min(dp[j], dp[j-k] + a[k] + 2);
            }
        }
    }
    return dp;
}
void foo() {
    int n, k; cin >> n >> k;
    trie_t *root = new_trie();
    repeat (i,n) {
        string s; cin >> s;
        trie_t *t = root;
        t->count += 1;
        for (char c : s) {
            t = get_valid_trie(t, c);
            t->count += 1;
        }
        t->exists = true;
    }
    cout << bar(root)[k] << endl;
    delete_trie(root);
}
int main() {
    int testcases; cin >> testcases;
    repeat (testcase, testcases) {
        cout << "Case #" << testcase+1 << ": ";
        foo();
    }
    return 0;
}
```
