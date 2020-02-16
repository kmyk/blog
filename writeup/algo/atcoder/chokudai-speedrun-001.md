---
layout: post
alias: "/blog/2017/07/28/chokudai-speedrun-001/"
date: "2017-07-28T22:04:36+09:00"
tags: [ "competitive", "writeup", "atcoder", "chokudai-speedrun" ]
"target_url": [ "https://beta.atcoder.jp/contests/chokudai_s001" ]
---

# Chokudai SpeedRun 001

## A - 最大値

`max`とか`std::max_element`とか

``` python
#!/usr/bin/env python3
_ = int(input())
print(max(list(map(int, input().split()))))
```

## B - 和

`sum`とか`std::accumulate`とか

``` python
#!/usr/bin/env python3
_ = input()
print(sum(map(int, input().split())))
```

## C - カンマ区切り

`tail -n 1`あるいは`read`を忘れてWAが生えた

``` sh
read;tr \  ,
```

## D - ソート

`sort`

``` python
#!/usr/bin/env python3
_ = input()
print(*sorted(map(int, input().split())))
```

## E - 1は何番目？

`list.index`や`std::find`

``` python
#!/usr/bin/env python3
_ = input()
print(list(map(int, input().split())).index(1) + 1)
```

## F - 見える数

問題文がすごく難しい。正解は$\\{ 1 \le i \le N \mid \forall j. 1 \le j \lt i \to a\_j \lt a\_i \\}$の要素数。

``` python
#!/usr/bin/env python3
n = int(input())
a = list(map(int, input().split()))
max_a_j = -1
result = 0
for a_i in a:
    result += (max_a_j < a_i)
    max_a_j = max(max_a_j, a_i)
print(result)
```

## G - あまり

多倍長整数は最高

``` python
#!/usr/bin/env python3
_ = int(input())
a = ''.join(input().split())
print(int(a) % (10 ** 9 + 7))
```

## H - LIS

$O(N\ log N)$。
貼る。あるいは検索。
ライブラリになかったので足しておいた。

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

template <typename T>
vector<T> longest_increasing_subsequence(vector<T> const & xs) {
    vector<T> l; // l[i] is the last element of the increasing subsequence whose length is i+1
    l.push_back(xs.front());
    for (auto && x : xs) {
        auto it = lower_bound(l.begin(), l.end(), x);
        if (it == l.end()) {
            l.push_back(x);
        } else {
            *it = x;
        }
    }
    return l;
}

int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    printf("%d\n", int(longest_increasing_subsequence(a).size()));
    return 0;
}
```

## I - 和がNの区間

しゃくとり法。$O(N)$。

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    int result = 0;
    for (int l = 0, r = 0, acc = 0; l < n; acc -= a[l], ++ l) {
        while (r < n and acc + a[r] <= n) { acc += a[r]; ++ r; }
        result += acc == n;
    }
    printf("%d\n", result);
    return 0;
}
```

## J - 転倒数

$O(N \log N)$。
ライブラリになかったので足しておいた2。

``` c++
#include <algorithm>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

template <typename Monoid>
struct binary_indexed_tree { // on monoid
    typedef typename Monoid::underlying_type underlying_type;
    vector<underlying_type> data;
    Monoid mon;
    binary_indexed_tree(size_t n, Monoid const & a_mon = Monoid()) : mon(a_mon) {
        data.resize(n, mon.unit());
    }
    void point_append(size_t i, underlying_type z) { // data[i] += z
        for (size_t j = i + 1; j <= data.size(); j += j & -j) data[j - 1] = mon.append(data[j - 1], z);
    }
    underlying_type initial_range_concat(size_t i) { // sum [0, i)
        underlying_type acc = mon.unit();
        for (size_t j = i; 0 < j; j -= j & -j) acc = mon.append(data[j - 1], acc);
        return acc;
    }
};
struct plus_t {
    typedef int underlying_type;
    int unit() const { return 0; }
    int append(int a, int b) const { return a + b; }
};

ll inversion_number(vector<int> const & a) {
    int n = a.size();
    binary_indexed_tree<plus_t> bit(n + 1);
    ll result = 0;
    repeat (i, n) {
        result += i - bit.initial_range_concat(a[i] + 1);
        bit.point_append(a[i], 1);
    }
    return result;
}

int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    ll result = inversion_number(a);
    printf("%lld\n", result);
    return 0;
}
```

## K - 辞書順で何番目？

$O(N \log N)$。$n\_i = \\{ j \mid i \lt j \land a\_i \gt a\_j \\}$として$1 + \sum\_i n\_i (n - i - 1)!$。

階乗進数ぽさがあったから上手にできないかなと思ったが思い付かず。

``` c++
#include <algorithm>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

template <typename Monoid>
struct binary_indexed_tree { // on monoid
    typedef typename Monoid::underlying_type underlying_type;
    vector<underlying_type> data;
    Monoid mon;
    binary_indexed_tree(size_t n, Monoid const & a_mon = Monoid()) : mon(a_mon) {
        data.resize(n, mon.unit());
    }
    void point_append(size_t i, underlying_type z) { // data[i] += z
        for (size_t j = i + 1; j <= data.size(); j += j & -j) data[j - 1] = mon.append(data[j - 1], z);
    }
    underlying_type initial_range_concat(size_t i) { // sum [0, i)
        underlying_type acc = mon.unit();
        for (size_t j = i; 0 < j; j -= j & -j) acc = mon.append(data[j - 1], acc);
        return acc;
    }
};
struct plus_t {
    typedef int underlying_type;
    int unit() const { return 0; }
    int append(int a, int b) const { return a + b; }
    int invert(int a) const { return - a; }
};
template <int mod>
int fact(int n) {
    static vector<int> memo(1, 1);
    if (memo.size() <= n) {
        int l = memo.size();
        memo.resize(n+1);
        repeat_from (i, l, n+1) memo[i] = memo[i-1] *(ll) i % mod;
    }
    return memo[n];
}

constexpr int mod = 1e9+7;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i, n) { scanf("%d", &a[i]); -- a[i]; }
    binary_indexed_tree<plus_t> bit(n + 1);
    repeat (i, n) bit.point_append(i, 1);
    ll result = 1;
    repeat (i, n) {
        result += bit.initial_range_concat(a[i]) *(ll) fact<mod>(n - i - 1) % mod;
        bit.point_append(a[i], -1);
    }
    result %= mod;
    printf("%lld\n", result);
    return 0;
}
```

## L - N回スワップ

$i - a\_i$に辺を張って無向グラフを作り連結成分数を$k$とする。
$n - k$回のswapでsortできてこれが最小。
置換の偶奇は変えられないので、$n - k \equiv 0 \pmod{2}$かどうかが答え。

``` python
#!/usr/bin/env python3
n = int(input())
a = list(map(lambda s: int(s) - 1, input().split()))
used = [ False ] * n
cnt = 0
for i in range(n):
    j = i
    used[j] = True
    while a[j] != j:
        j = a[j]
        if used[j]:
            break
        used[j] = True
        cnt += 1
print(['NO', 'YES'][(n - cnt) % 2 == 0])
```
