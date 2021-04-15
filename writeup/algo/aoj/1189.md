---
layout: post
redirect_from:
  - /writeup/algo/aoj/1189/
  - /blog/2017/12/08/aoj-1189/
date: 2017-12-08T06:02:32+09:00
tags: [ "competitive", "writeup", "aoj", "dp" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1189" ]
---

# AOJ 1189. 素数洞穴 / Prime Caves

解いたのは10/19の茶会。

## solution

DP。$O(M)$。

まず、洞穴を表す二次元配列を用意しその番号が素数であるかを書き込んでいく。
これは面倒をやるだけ。
それさえできれば後は上から下へDPをすればよい。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

vector<bool> sieve_of_eratosthenes(int n) { // enumerate primes in [2,n] with O(n log log n)
    vector<bool> is_prime(n + 1, true);
    is_prime[0] = is_prime[1] = false;
    for (int i = 2; i * i <= n; ++i)
        if (is_prime[i])
            for (int k = 2 * i; k <= n; k += i)
                is_prime[k] = false;
    return is_prime;
}

constexpr int max_n = 1000000;
constexpr int sqrt_max_n = 1000;
constexpr int height = sqrt_max_n + 100;
constexpr int width = sqrt_max_n + 100;
constexpr int center_y = height / 2;
constexpr int center_x = width / 2;
const int dy[] = { 0, -1, 0, 1 };  // RULD
const int dx[] = { 1, 0, -1, 0 };

int main() {
    // fill the caves
    auto cave = vectors(height, width, int());
    vector<pair<int16_t, int16_t> > rev_cave(max_n + 1);
    {
        int y = center_y;
        int x = center_x;
        int dir = 3;  // D
        repeat (i, max_n) {
            cave[y][x] = i + 1;
            rev_cave[i + 1] = { y, x };
            int ly = y + dy[(dir + 1) % 4];
            int lx = x + dx[(dir + 1) % 4];
            if (not cave[ly][lx]) {
                dir = (dir + 1) % 4;
            }
            y += dy[dir];
            x += dx[dir];
        }
    }
    auto is_prime = sieve_of_eratosthenes(max_n);
    // solve
    while (true) {
        // input
        int m, n; scanf("%d%d", &m, &n);
        if (m == 0 and n == 0) break;
        // dp
        auto dp = vectors(height, width, int());
        int y, lx; tie(y, lx) = rev_cave[n];
        int rx = lx + 1;
        pair<int, int> result = {};
        while (y < height) {
            repeat_from (x, lx, rx) {
                int k = cave[y][x];
                if (k and k <= m) {
                    dp[y][x] = max({ dp[y - 1][x - 1], dp[y - 1][x], dp[y - 1][x + 1] });
                    if (is_prime[k]) {
                        dp[y][x] += 1;
                        setmax(result, make_pair(dp[y][x], k));
                    }
                }
            }
            // incr
            ++ y;
            lx = max(1, lx - 1);
            rx = min(width - 1, rx + 1);
        }
        // output
        if (result.first == 0) result.second = 0;
        printf("%d %d\n", result.first, result.second);
    }
    return 0;
}
```
