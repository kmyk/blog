---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/world-codesprint-8-sherlock-and-nim/
  - /blog/2016/12/20/world-codesprint-8-sherlock-and-nim/
date: "2016-12-20T02:33:06+09:00"
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint", "dp", "oeis" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-8/challenges/sherlock-and-nim" ]
---

# HackerRank World CodeSprint 8: Return of the Nim

## problem

Nimを拡張したゲームを考える。
複数の石の山があって、以下の操作のうち好きな方を選んで行うことを交互に繰り返し、先に操作できなくなったプレイヤーの負け。

-   ある正の数$k$を選び、ある山から$k$個の石を取り去る。 (普通のnim)
-   ある正の数$k$を選び、全ての山から$k$個の石を取り去る。

石が足りなくなるような$k$は選べず、また$0$個の石の山は山として扱う(のでそれが存在すると全体から取り去ることができなくなる)。

ただし、石の山の数$n$は素数。

## solution

If $n$ is an odd prime, the winner is the same to the ordinal nim. i.e., the grundy number is the xor-sum of the numbers of stones.
If $n$ is $2$, the even prime, the first player almost always wins.
The second player wins at some numbers of stones, $(0, 0), (1, 2), (2, 1), (3, 5), (4, 7), (5, 3), \dots$, and this is <https://oeis.org/A002251>.


## implementation

``` c++
#include <iostream>
#include <vector>
#include <numeric>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;

vector<int> const & a002251() {
    static vector<int> a;
    if (a.empty()) {
        const int max_p = 100000;
        a.resize(max_p + 1);
        repeat (k,max_p) {
            const long double eps = 1e-18;
            int l = floor(k *     (1+sqrtl(5))/2     + eps);
            int u = floor(k * pow((1+sqrtl(5))/2, 2) + eps);
            if (l <= max_p) a[l] = u;
            if (u <= max_p) a[u] = l;
        }
    }
    return a;
};

bool solve(int n, vector<int> & piles) {
    if (n == 2) {
        // https://oeis.org/A002251
        int a = min(piles[0], piles[1]);
        int b = max(piles[0], piles[1]);
        return a002251()[a] != b;
    } else {
        // assert (is_prime(n));
        return whole(accumulate, piles, 0, bit_xor<int>());
    }
}
int main() {
    int games; cin >> games;
    while (games --) {
        int n; cin >> n;
        vector<int> piles(n); repeat (i,n) cin >> piles[i];
        cout << (solve(n, piles) ? "Sherlock" : "Watson") << endl;
    }
    return 0;
}
```
