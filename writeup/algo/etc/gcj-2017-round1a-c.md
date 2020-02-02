---
layout: post
alias: "/blog/2017/04/23/gcj-2017-round1a-c/"
date: "2017-04-23T01:08:38+09:00"
title: "Google Code Jam 2017 Round 1A: C. Play the Dragon"
tags: [ "competitive", "writeup", "gcj", "aws" ]
"target_url": [ "https://code.google.com/codejam/contest/5304486/dashboard#s=p2" ]
---

## solution

Buf/Debufの回数を全探索。task並列化して計算資源で殴る。$O(A\_k/D + \sqrt{H\_k})$。

命令の使い方はDebuf $\to$ Buf $\to$ Attackの順で、適宜Cureを差し込むのが最適。
倒すのにBuf + Attackが何回必要かはBufの回数を総当たり。ただし上限は$\sqrt{H\_k}$回でよい。これはほぼ無視できる。
Debufの上限は$A\_k/D$回である。これは無視できない。

無視できないとはいえ$A\_k/D \le 10^9$なので、間に合わないこともない。
定数倍高速化をきちんとやれば間に合うだろうし、並列化すれば確実。

例として、並列化なしで手元実行:

```
real    13m41.437s
user    13m37.268s
sys     0m0.572s
```

`-fopenmp`を付けてAWS c4.8xlarge上(36論理コア)で実行:

```
real    0m35.823s
user    15m46.604s
sys     0m0.352s
```

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <tuple>
#include <cmath>
#include <omp.h>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

constexpr ll infll = ll(1e18)+9;
ll solve(ll hd, ll ad, ll hk, ll ak, ll b, ll d) {
    ll turns_to_kill = infll; { // if no cure / debuf are required, this value is the result
        int buf_count_limit = sqrt(hk) + 100;
        repeat (buf, buf_count_limit) {
            ll buffed_ad = ad + buf * b; // Buf
            setmin(turns_to_kill, buf + (hk + buffed_ad-1) / buffed_ad); // Attack
        }
    }
    ll result = infll;
    int debuf_count_limit = d == 0 ? 0 : ak / d + 3;
    ll turns_to_debuf = 0;
    ll hd_after_debuf = hd;
    repeat (debuf, debuf_count_limit+1) {
        ll debuffed_ak = ak - debuf * d;
        if (debuffed_ak <= 0) {
            setmin(result, turns_to_debuf + turns_to_kill);
            break;
        }
        ll initial_turns_to_cure = (hd_after_debuf - 1) / debuffed_ak;
        ll turns_to_cure = (hd - 1) / debuffed_ak - 1;
        if ((turns_to_kill - 1) <= initial_turns_to_cure) {
            setmin(result, turns_to_debuf + turns_to_kill);
        } else if (turns_to_cure >= 1) {
            ll remaining_turns_to_kill = turns_to_kill - initial_turns_to_cure;
            ll cure_count = ((remaining_turns_to_kill - 1) + turns_to_cure - 1) / turns_to_cure;
            setmin(result, turns_to_debuf + turns_to_kill + cure_count);
        }
        ll next_debuffed_ak = max<ll>(0, debuffed_ak - d);
        if (hd_after_debuf <= next_debuffed_ak) {
            hd_after_debuf = hd - debuffed_ak; // Cure
            turns_to_debuf += 1;
            if (hd_after_debuf <= next_debuffed_ak) break;
        }
        hd_after_debuf -= next_debuffed_ak; // Debuf
        turns_to_debuf += 1;
    }
    return result;
}

int main() {
    int t; scanf("%d", &t);
    vector<tuple<int, int, int, int, int, int> > query(t);
    repeat (x,t) {
        int hd, ad, hk, ak, b, d; scanf("%d%d%d%d%d%d", &hd, &ad, &hk, &ak, &b, &d);
        query[x] = make_tuple(hd, ad, hk, ak, b, d);
    }
    vector<ll> result(t);
#pragma omp parallel for schedule(dynamic)
    repeat (x,t) {
        int hd, ad, hk, ak, b, d; tie(hd, ad, hk, ak, b, d) = query[x];
        result[x] = solve(hd, ad, hk, ak, b, d);
        fprintf(stderr, "Case #%d: %lld\n", x+1, result[x]);
    }
    repeat (x,t) {
        printf("Case #%d: ", x+1);
        if (result[x] == infll) {
            printf("IMPOSSIBLE\n");
        } else {
            printf("%lld\n", result[x]);
        }
    }
    return 0;
}
```
