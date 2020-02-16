---
layout: post
redirect_from:
  - /blog/2017/03/07/yahoo-procon-2017-qual-c/
date: "2017-03-07T17:21:09+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2017-qual/tasks/yahoo_procon2017_qual_c" ]
---

# 「みんなのプロコン」: C - 検索

適当に構成すればできるでしょと思ってやったら$1$WA生やした。

## solution

$A$中の文字列の最長共通接頭辞$s$を求め、$s$と他の文字列との共通接頭辞の最短$+1$の長さに切り詰め、最後に妥当性の確認をする。
$O(\sum_i \|S_i\|)$。$\sum_i \|S_i\| \le 10^5$の制約により間に合う。

## implementation

提出したらclangの方が$1.6$倍ぐらい実行時間がかかってた。
入出力とかなのかな。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <unordered_set>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
int common_prefix_length(string const & a, string const & b, int limit) {
    int i = 0;
    while (i < a.length() and i < b.length() and i < limit and a[i] == b[i]) ++ i;
    return i;
}
constexpr int inf = 1e9+7;
int main() {
    // input
    int n, k; cin >> n >> k;
    vector<int> a(k); repeat (i,k) { cin >> a[i]; -- a[i]; }
    // upper bound
    unordered_set<int> a_set;
    repeat (i,k) a_set.insert(a[i]);
    vector<string> s(n); repeat (i,n) cin >> s[i];
    whole(sort, a);
    int a_common = inf;
    repeat (i,k-1) {
        a_common = common_prefix_length(s[a[i]], s[a[i+1]], a_common);
    }
    assert (not a.empty());
    // lower bound
    string t = s[a.front()].substr(0, a_common);
    int a_index = 0;
    int b_common = 0;
    repeat (i,n) {
        if (a_index < a.size() and a[a_index] == i) {
            ++ a_index;
        } else {
            int j = common_prefix_length(t, s[i], inf) + 1;
            setmax(b_common, j);
        }
    }
    // check
    string result = t.substr(0, b_common);
    bool valid = true;
    repeat (i,n) {
        int l = common_prefix_length(result, s[i], inf);
        if ((l == result.size()) != (a_set.count(i))) {
            valid = false;
        }
    }
    // output
    if (not valid) {
        cout << -1 << endl;
    } else {
        cout << result << endl;
    }
    return 0;
}
```
