---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_074_e/
  - /writeup/algo/atcoder/arc-074-e/
  - /blog/2017/05/20/arc-074-e/
date: "2017-05-20T22:32:39+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc074/tasks/arc074_c" ]
---

# AtCoder Regular Contest 074: E - RGB Sequence

overflowでたくさんWAを生やした。
clangかつ`-fsanitize=undefined`だと`bitset`と`std::hash`の周りでコンパイルこけるのが悪い、と思ったけど問題となるテストケース作ってなかったのでいずれにせよだめ。

## solution

`unordered_map<bitset<3*MAX_N>, int>`な動的計画法。計算量解析は難しいが、自明な上界は$O(N 3^M)$。非想定っぽい。

各クエリがその区間中にどの色を持っているかを`bitset<3*MAX_N>`で表し、これの上で状態遷移させる。
無効な状態は積極的に消去し、また不要になったクエリの情報は全て塗り潰して状態をまとめる。
これらをきちんとやれば間に合う。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <bitset>
#include <tuple>
#include <unordered_map>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

constexpr int mod = 1e9+7;
constexpr int MAX_M = 300;
int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<int> l(m), r(m), x(m); repeat (i,m) { scanf("%d%d%d", &l[i], &r[i], &x[i]); -- l[i]; } // [l, r)
    assert (m <= MAX_M);
    // dp
    unordered_map<bitset<3*MAX_M>, int> cur;
    unordered_map<bitset<3*MAX_M>, int> prv;
    cur[bitset<3*MAX_M>()] += 1;
    vector<int> queries;
    repeat (i,n) {
        cur.swap(prv);
        cur.clear();
        repeat (j,m) if (l[j] == i) {
            queries.push_back(j);
        }
        whole(sort, queries);
        repeat (c,3) { // RGB
            for (auto && it : prv) {
                bitset<3*MAX_M> s; int cnt; tie(s, cnt) = it;
                for (int j : queries) {
                    s[3*j+c] = true;
                    if (s[3*j+0] + s[3*j+1] + s[3*j+2] > x[j]) {
                        cnt = 0;
                        break;
                    }
                }
                if (cnt) {
                    cur[s] += cnt;
                    cur[s] %= mod;
                }
            }
        }
        cur.swap(prv);
        cur.clear();
        for (auto && it : prv) {
            bitset<3*MAX_M> s; int cnt; tie(s, cnt) = it;
            for (int j : queries) if (r[j]-1 == i) {
                if (s[3*j+0] + s[3*j+1] + s[3*j+2] != x[j]) {
                    cnt = 0;
                    break;
                }
                s[3*j+0] = false;
                s[3*j+1] = false;
                s[3*j+2] = false;
            }
            if (cnt) {
                cur[s] += cnt;
                cur[s] %= mod;
            }
        }
        repeat (j,m) if (r[j]-1 == i) {
            queries.erase(whole(remove, queries, j), queries.end());
        }
    }
    assert (queries.size() == 0);
    ll result = 0;
    for (auto && it : cur) {
        result += it.second;
    }
    result %= mod;
    // output
    printf("%lld\n", result);
    return 0;
}
```
