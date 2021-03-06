---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/407/
  - /blog/2016/10/19/yuki-407/
date: "2016-10-19T17:21:33+09:00"
tags: [ "competitive", "writeup", "yukicoder", "prime", "sieve-of-eratosthenes" ]
"target_url": [ "http://yukicoder.me/problems/no/407" ]
---

# Yukicoder No.407 鴨等素数間隔列の数え上げ

つくば遠征後の休息や出場予定のコンテストの準備のために今日も学校をさぼった。
今日の講義の$\frac{2}{3}$が休講なのもあって、ついやってしまった。
さすがに明日は出ます。

## solution

eratosthenesの篩で全ての可能な$d$を全て列挙して足し合わせる。$d$が決まれば$x_0$は$\max \\{ 0, l - d(n-1) + 1 \\}$通り。$O(L \log \log L)$。

## implementation

``` c++
#include <iostream>
#include <vector>
typedef long long ll;
using namespace std;
vector<int> sieve_of_eratosthenes(int n) { // enumerate primes in [2,n] with O(n log log n)
    vector<bool> is_prime(n+1, true);
    is_prime[0] = is_prime[1] = false;
    for (int i = 2; i*i <= n; ++i)
        if (is_prime[i])
            for (int k = i+i; k <= n; k += i)
                is_prime[k] = false;
    vector<int> primes;
    for (int i = 2; i <= n; ++i)
        if (is_prime[i])
            primes.push_back(i);
    return primes;
}
int main() {
    int n, l; cin >> n >> l;
    vector<int> primes = sieve_of_eratosthenes(l);
    ll ans = 0;
    for (int d : primes) {
        int k = l - d * (n-1) + 1;
        if (k < 0) break;
        ans += k;
    }
    cout << ans << endl;
    return 0;
}
```
