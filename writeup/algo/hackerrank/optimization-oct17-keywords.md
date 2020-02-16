---
layout: post
alias: "/blog/2017/11/10/hackerrank-optimization-oct17-keywords/"
date: "2017-11-10T22:51:57+09:00"
tags: [ "competitive", "writeup", "hackerrank" ]
"target_url": [ "https://www.hackerrank.com/contests/optimization-oct17/challenges/keywords" ]
---

# HackerRank Performance Optimization: C. Keywords

## problem

単語列$s$と単語の集合$\mathrm{keys}$が与えられる。$s$の連続部分列で$\mathrm{keys}$を単語として全て含むものを探し、そのようなものの文字列としての長さの最小値を答えよ。

## implementation

``` c++
...

#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

constexpr int inf = 1e9+7;
int minimumLength(string const & text, vector<string> const & keys) {
    int n = text.length();
    vector<uint16_t> found(n + 1);
    for (int l = 0; l < n; ) {
        if (text[l] == ' ') {
            ++ l;
        } else {
            int r = text.find(' ', l);
            if (r == string::npos) r = n;
            repeat (k, keys.size()) {
                if (text.compare(l, r - l, keys[k]) == 0) {
                    found[r] |= 1 << k;
                }
            }
            l = r;
        }
    }
    vector<vector<int> > next(keys.size(), vector<int>(n + 30, inf));
    repeat (k, keys.size()) {
        if (found[n] & (1 << k)) next[k][n] = n;
    }
    repeat_reverse (i, n) {
        repeat (k, keys.size()) {
            next[k][i] = next[k][i + 1];
            if (found[i] & (1 << k)) next[k][i] = i;
        }
    }
    int result = inf;
    repeat (i, n) {
        int acc = 0;
        repeat (k, keys.size()) {
            setmax(acc, next[k][i + keys[k].length()]);
        }
        setmin(result, acc - i);
    }
    if (result > n) result = -1;
    return result;
}

...
```
