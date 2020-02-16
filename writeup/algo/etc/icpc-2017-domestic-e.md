---
layout: post
alias: "/blog/2017/07/14/icpc-2017-domestic-e/"
date: "2017-07-14T23:50:41+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-domestic", "parsing", "math" ]
---

# ACM-ICPC 2017 国内予選: E. 論理式圧縮機

## solution

文法はLL(1)なので再帰下降構文解析やるだけ。
ここで定義される論理式$E$は$4$つの真偽値$a, b, c, d \in 2 = \\{ 0, 1 \\}$から真偽値への関数と見做せる。
つまり$E : 2^4 \to 2$であり、そのような関数はちょうど$65536 = 2^{2^4}$種しかない。
これら全てに対してそれを表現するのに必要な記号列の長さを事前計算しておけば、各クエリに対しては構文解析$O(\|E\|)$の後に表引きで$O(1)$で答えられる。
表の構築は、例えばBellman-Ford法のように、変化がなくなるまで更新し続けるDPで無理矢理やればよい。

## implementation

``` c++
#include <bitset>
#include <cassert>
#include <iostream>
#include <queue>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < (n); ++ (i))
using namespace std;

//                         fed          210
const bitset<16> bitset_a("1111111100000000");
const bitset<16> bitset_b("1111000011110000");
const bitset<16> bitset_c("1100110011001100");
const bitset<16> bitset_d("1010101010101010");
bitset<16> evaluate(string::const_iterator & first, string::const_iterator last) {
    assert (first != last);
    if (*first == '0') {
        ++ first;
        return bitset<16>();
    } else if (*first == '1') {
        ++ first;
        return bitset<16>().flip();
    } else if (*first == 'a') {
        ++ first;
        return bitset_a;
    } else if (*first == 'b') {
        ++ first;
        return bitset_b;
    } else if (*first == 'c') {
        ++ first;
        return bitset_c;
    } else if (*first == 'd') {
        ++ first;
        return bitset_d;
    } else if (*first == '-') {
        ++ first;
        return bitset<16>(evaluate(first, last)).flip();
    } else {
        assert (*first == '(');
        ++ first;
        auto l = evaluate(first, last);
        char op = *first;
        ++ first;
        auto r = evaluate(first, last);
        assert (*first  == ')');
        ++ first;
        if (op == '^') {
            return l ^ r;
        } else if (op == '*') {
            return l & r;
        } else {
            assert (false);
        }
    }
}
bitset<16> evaluate(string const & s) {
    string::const_iterator it = s.begin();
    auto value = evaluate(it, s.end());
    assert (it == s.end());
    return value;
}

constexpr int inf = 1e9+7;
vector<int> generate_table() {
    vector<int> table(1 << 16, inf);
    queue<pair<int, int> > que;
    auto push = [&](bitset<16> value, int length) {
        if (length < table[value.to_ulong()]) {
            table[value.to_ulong()] = length;
            que.emplace(length, value.to_ulong());
        }
    };
    push(bitset<16>(), 1); // 0
    push(bitset<16>().flip(), 1); // 1
    push(bitset_a, 1);
    push(bitset_b, 1);
    push(bitset_c, 1);
    push(bitset_d, 1);
    while (not que.empty()) {
        int int_value, length; tie(length, int_value) = que.front(); que.pop();
        if (table[int_value] < length) continue;
        bitset<16> value(int_value);
        repeat (i, 1<<16) if (table[i] != inf) {
            push(bitset<16>(value).flip(), length + 1);
            push(value ^ bitset<16>(i), length + table[i] + 3);
            push(value & bitset<16>(i), length + table[i] + 3);
        }
    }
    return table;
}

int main() {
    auto table = generate_table();
    while (true) {
        string s; cin >> s;
        if (s == ".") break;
        auto value = evaluate(s);
        cout << table[value.to_ulong()] << endl;
    }
}
```
