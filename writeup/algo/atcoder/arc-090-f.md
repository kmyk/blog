---
layout: post
alias: "/blog/2018/04/09/arc-090-f/"
date: "2018-04-09T23:19:44+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "counting" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc090/tasks/arc090_d" ]
---

# AtCoder Regular Contest 090: F - Number of Digits

## solution

組$[l, r]$を次の$3$種に分ける。$O(s)$。

1.  $f(l) \gt 8$ かつ $f(l) = f(r )$
1.  $f(l) \gt 8$ かつ $f(l) \ne f(r )$
1.  $f(l) \le 8$

先に3番について。
小さいところでは次のような抜けが存在しており面倒。このためしゃくとり法で全列挙する。

-   $181 = 1 + 1 + 1 + \underbrace{2 + 2 + 2 + \dots + 2}\_{89}$
-   $182 = 1 + 1 + \underbrace{2 + 2 + 2 + \dots + 2}\_{90}$
-   $184 = 1 + \underbrace{2 + 2 + 2 + \dots + 2}\_{90} + 3$

3番以外では$\\#\\{ x \mid f(x) = f(l) \\} \ge s$が言える。

1番のような$l$は$s$の約数のみなので列挙すればよい。
それぞれの$f(l)$について$\\#\\{ x \mid f(x) = f(l) \\} - s / f(l) + 1$個ある。

2番では$f(r ) = f(l) + 1$しかありえず、区間の長さ$r - l$に対し区間$[l, r]$が一意になる。
区間の長さは$f(l) \ge 8$である限り自由に取れるので、この長さの上限を求めればよい。
ただし区間の長さから導こうとすると1番の場合が混ざるので適当に除く。

## note

-   おおまかな方向はすぐに見えたのに実装がだめすぎた

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define unittest_name_helper(counter) unittest_ ## counter
#define unittest_name(counter) unittest_name_helper(counter)
#define unittest __attribute__((constructor)) void unittest_name(__COUNTER__) ()
using ll = long long;
using namespace std;

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? r : l) = m;
    }
    return r;
}

vector<bool> sieve_of_eratosthenes(int n) {
    vector<bool> is_prime(n, true);
    is_prime[0] = is_prime[1] = false;
    for (int i = 2; i *(ll) i < n; ++ i)
        if (is_prime[i])
            for (int k = 2 * i; k < n; k += i)
                is_prime[k] = false;
    return is_prime;
}
vector<int> list_primes(int n) {
    auto is_prime = sieve_of_eratosthenes(n);
    vector<int> primes;
    for (int i = 2; i < n; ++ i)
        if (is_prime[i])
            primes.push_back(i);
    return primes;
}
map<ll, int> prime_factorize(ll n, vector<int> const & primes) {
    map<ll, int> result;
    for (int p : primes) {
        if (n < p *(ll) p) break;
        while (n % p == 0) {
            result[p] += 1;
            n /= p;
        }
    }
    if (n != 1) result[n] += 1;
    return result;
}
vector<ll> list_factors(ll n, vector<int> const & primes) {
    vector<ll> result;
    result.push_back(1);
    for (auto it : prime_factorize(n, primes)) {
        ll p; int k; tie(p, k) = it;
        int size = result.size();
        REP (y, k) {
            REP (x, size) {
                result.push_back(result[y * size + x] * p);
            }
        }
    }
    return result;
}

template <int32_t MOD>
struct mint {
    int32_t data;
    mint() = default;
    mint(int32_t value) : data(value) {}
    inline mint<MOD> operator + (mint<MOD> other) const { int32_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int32_t c = this->data - other.data; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int32_t c = this->data * int64_t(other.data) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->data += other.data; if (this->data >= MOD) this->data -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->data -= other.data; if (this->data <    0) this->data += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->data = this->data * int64_t(other.data) % MOD; if (this->data < 0) this->data += MOD; return *this; }
    mint<MOD> pow(uint64_t k) const {
        mint<MOD> x = *this;
        mint<MOD> y = 1;
        for (uint64_t i = 1; i and (i <= k); i <<= 1) {
            if (k & i) y *= x;
            x *= x;
        }
        return y;
    }
};

constexpr int MOD = 1e9 + 7;

mint<MOD> cnt_f_inv(int x) {
    return mint<MOD>(10).pow(x - 1) * 9;
}
double cnt_inv_f_float(int x) {
    return pow(10, x - 1) * 9;
}

ll lower_from(int f_n, int len) {
    if (len == 0) return 0;
    if (cnt_inv_f_float(f_n) >= len) {
        return f_n *(ll) len;
    } else {
        int width = cnt_f_inv(f_n).data;
        return f_n *(ll) width + lower_from(f_n + 1, len - width);
    }
}
ll upper_from(int f_n, int len) {
    if (len == 0) return 0;
    return f_n + lower_from(f_n + 1, len - 1);
}
bool delta_f(int n) {
    return
        n == 10 or
        n == 100 or
        n == 1000 or
        n == 10000 or
        n == 100000 or
        n == 1000000 or
        n == 10000000 or
        n == 100000000 or
        n == 1000000000;
}

unittest {
    assert (cnt_f_inv(1).data == 9);
    assert (cnt_f_inv(2).data == 90);
    assert (cnt_f_inv(3).data == 900);
    assert (lower_from(1, 1000) == 1 * 9 + 2 * 90 + 3 * 900 + 4);
    assert (lower_from(2, 1000) == 2 * 90 + 3 * 900 + 4 * 10);
    assert (lower_from(100, 1000) == 100 * 1000);
}

int solve(int s) {
    mint<MOD> acc = 0;
    // case f_l > 8 and s % f_l = 0
    vector<int> used_len;
    for (int f_l : list_factors(s, list_primes(sqrt(s) + 3))) {
        if (f_l <= 8) continue;
        int len = s / f_l;
        if (lower_from(f_l, len) <= s and s <= upper_from(f_l, len)) {
            acc += cnt_f_inv(f_l) - len + 1;
        }
        used_len.push_back(len);
    }
    // case f_l > 8 and s % f_l != 0
    acc += binsearch(1, s, [&](int len) {
        int f_l = binsearch(0, s + 1, [&](int f_l) {
            return s < lower_from(f_l + 1, len);
        });
        return f_l <= 8;
    });
    acc -= used_len.size() + 1;
    // case f_l <= 8
    for (int l = 1, r = 1, sum = 0, f_l = 1, f_r = 1; f_l <= 8;) {
        while (sum + f_r <= s) {
            sum += f_r;
            ++ r;
            f_r += delta_f(r);
        }
        if (sum == s) acc += 1;
        sum -= f_l;
        ++ l;
        f_l += delta_f(l);
    }
    return acc.data;
}

int main() {
    int s; cin >> s;
    cout << solve(s) << endl;
    return 0;
}
```
