---
layout: post
alias: "/blog/2018/03/26/volgactf-2018-quals-golden-antelope/"
date: "2018-03-26T00:00:03+09:00"
tags: [ "ctf", "writeup", "volgactf", "crypto", "pseudo-random-number-generator" ]
"target_url": [ "https://quals.2018.volgactf.ru/tasks" ]
---

# VolgaCTF 2018 Quals: Golden Antelope

## problem

数字を予想するカジノ。乱数予測せよ。

## solution

生成器の状態を下の方から順に決定していけばよい。
最初と最後だけざっくり総当たりする。
`RB`だけ状態の進みが速いことと$31$byte目が最初は後から効いてくることに注意。

## note

-   「これはguessingすぎるでしょsolvedが正になるまで様子見」と判断して寝て起きたら「scriptの添付忘れてたよごめんね」というHintが増えてた
-   どちらかと言えばPPC

## implementation

``` c++
// $ g++ -std=c+=14 main.cpp -l boost_system -l pthread -l crypto
#include <bits/stdc++.h>
#include <boost/asio.hpp>
#include <openssl/sha.h>

#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;


const uint8_t L[256] = {
    0xf1, 0xef, 0x29, 0xbe, 0xb8, 0xf6, 0x4f, 0xaf, 0xb2, 0x92, 0xe3, 0xfc, 0xc6, 0x72, 0x48, 0xc3,
    0xbf, 0xa0, 0x10, 0xd1, 0x23, 0x34, 0x0c, 0x07, 0x7c, 0xf8, 0xae, 0xe8, 0xc9, 0xe1, 0x38, 0x36,
    0x4c, 0x2c, 0x0b, 0x70, 0x7b, 0xe7, 0xd7, 0xc5, 0xac, 0x57, 0xab, 0xd5, 0x4b, 0x77, 0xa5, 0xce,
    0xee, 0xf4, 0x47, 0x25, 0x8a, 0xf3, 0xfd, 0xbb, 0x5c, 0xe0, 0x2a, 0x19, 0x5d, 0xeb, 0xa6, 0x81,
    0x12, 0x61, 0x59, 0xcf, 0xc8, 0xa8, 0xfe, 0x3e, 0x31, 0x1e, 0x46, 0x7e, 0x3d, 0xd0, 0x3c, 0xc7,
    0xdc, 0x33, 0x8f, 0xca, 0x78, 0x6f, 0x0d, 0x62, 0x9d, 0xd9, 0x89, 0x73, 0x8c, 0x4e, 0xb7, 0xc0,
    0x03, 0x56, 0xb9, 0x79, 0x75, 0xda, 0x6e, 0x1c, 0xff, 0x67, 0x2f, 0xbc, 0x69, 0x91, 0x2b, 0x9b,
    0x7f, 0x17, 0x01, 0xde, 0xfa, 0x4a, 0x02, 0x0e, 0x8b, 0xa9, 0x58, 0x2d, 0xd8, 0xf9, 0x3b, 0xb3,
    0x49, 0x65, 0xcc, 0xa3, 0xbd, 0x16, 0x21, 0xd3, 0xe5, 0xd6, 0x42, 0x60, 0x4d, 0x20, 0x97, 0x5e,
    0x2e, 0xe9, 0x18, 0xc2, 0x63, 0x64, 0xf5, 0x6a, 0xd2, 0x68, 0x1b, 0x1f, 0xc4, 0xea, 0x74, 0xa2,
    0x45, 0x82, 0xb6, 0x32, 0x84, 0xed, 0x50, 0x26, 0xcb, 0x5f, 0x37, 0xa1, 0x15, 0xa4, 0x51, 0x53,
    0xb4, 0x09, 0xaa, 0x1a, 0x14, 0x43, 0xba, 0xdf, 0x87, 0x66, 0x85, 0x52, 0x3a, 0x28, 0x9a, 0xb1,
    0x44, 0x9f, 0x96, 0x41, 0xdd, 0x86, 0x88, 0x9e, 0x71, 0xb0, 0x13, 0x98, 0xe4, 0x05, 0xf7, 0x6c,
    0xb5, 0x93, 0x8e, 0x55, 0xec, 0x8d, 0xf2, 0x6d, 0x9c, 0xa7, 0xad, 0x00, 0x08, 0xf0, 0xe6, 0x6b,
    0x7a, 0xcd, 0xfb, 0x80, 0x0a, 0x83, 0x27, 0x39, 0x30, 0x06, 0x76, 0x90, 0x94, 0x35, 0x54, 0x04,
    0x0f, 0xc1, 0x5b, 0x99, 0x11, 0x40, 0x5a, 0xd4, 0xe2, 0x95, 0x3f, 0x22, 0x7d, 0x24, 0x1d, 0xdb,
};
const vector<int> X { 0, 4, 5, 8, 9, 10, 13, 15, 17, 18, 27, 31 };
const vector<int> A0 { 0, 1, 3, 4, 6, 7,    9, 10, 11,     15,     21, 22,         25,     31 };
const vector<int> A1 { 0, 1,       6, 7, 8, 9, 10,     12,     16, 21, 22, 23, 24, 25, 26, 31 };
const vector<int> B { 0, 2, 5, 14, 15, 19, 20, 30, 31 };

uint8_t H(bitset<32> const & state) {
    int y = 0;
    REP (i, 8) {
        y |= state[24 + i] << i;
    }
    return y;
}

bitset<32> next_state(bitset<32> const & state, vector<int> const & indices) {
    int y = 0;
    for (int i : indices) {
        y ^= int(state[i]);
    }
    return (state << 1) | bitset<32>(y);
}

uint8_t generate_destructive(bitset<32> & x, bitset<32> & a, bitset<32> & b) {
    x = next_state(x, X);
    if (x[29] == 0) {
        a = next_state(a, A0);
    } else {
        a = next_state(a, A1);
    }
    if (x[26] == 0) {
        b = next_state(b, B);
    } else {
        b = next_state(b, B);
        b = next_state(b, B);
    }
    return (H(x) + L[H(a)] + L[H(b)]) % 256;
}
uint8_t generate(bitset<32> x, bitset<32> a, bitset<32> b) {
    return generate_destructive(x, a, b);
}
uint8_t generate_nth(int n, bitset<32> x, bitset<32> a, bitset<32> b) {
    while (n --) {
        generate_destructive(x, a, b);
    }
    return generate_destructive(x, a, b);
}


struct state_t {
    int i;
    int b_delta;
    bitset<32> x;
    bitset<32> a;
    bitset<32> b;
};

constexpr int points = 30;
constexpr int points_total = 108;
state_t reconstruct(vector<uint8_t> const & history) {
    assert (history.size() == points - 1);
    queue<state_t> que;
    REP (x, 0x100) {
        REP (a, 0x100) {
            REP (b, 0x100) {
                state_t s = {};
                s.i = 0;
                s.b_delta = 0;
                s.x = bitset<32>(x) << 23;  // 23 = 32 - 8 - 1
                s.a = bitset<32>(a) << 23;
                s.b = bitset<32>(b) << 23;
                if (not s.x[26]) {
                    if (generate_nth(s.i, s.x, s.a, s.b) == history[s.i]) {
                        que.push(s);
                    }
                } else {
                    s.b_delta += 1;
                    REP (b2, 2) {
                        s.b[23 - s.i - s.b_delta] = b2;
                        if (generate_nth(s.i, s.x, s.a, s.b) == history[s.i]) {
                            que.push(s);
                        }
                    }
                }
            }
        }
    }
    while (not que.empty()) {
        state_t s = que.front();
        if (23 - (s.i + 1) - s.b_delta < 0) break;
        que.pop();
        REP (x, 2) {
            REP (a, 2) {
                REP (b, 2) {
                    state_t t = s;
                    t.i += 1;
                    int i = 23 - t.i;
                    int j = 23 - t.i - t.b_delta;
                    if (i >= 0) t.x[i] = x;
                    if (i >= 0) t.a[i] = a;
                    if (j >= 0) t.b[j] = b;
                    if (not s.x[26 - t.i] or j - 1 < 0) {
                        if (generate_nth(t.i, t.x, t.a, t.b) == history[t.i]) {
                            que.push(t);
                        }
                    } else {
                        t.b_delta += 1;
                        REP (b2, 2) {
                            t.b[23 - t.i - t.b_delta] = b2;
                            if (generate_nth(t.i, t.x, t.a, t.b) == history[t.i]) {
                                que.push(t);
                            }
                        }
                    }
                }
            }
        }
    }
    assert (not que.empty());
    state_t s = que.front();
    REP (x31, 2) REP (a31, 2) REP (b31, 2) REP (b30, 2) {
        REP (x, 0x400) REP (a, 0x400) {
            state_t t = s;
            t.x ^=  bitset<32>(x)          ^ (bitset<32>(x31) << 31);
            t.a ^=  bitset<32>(a)          ^ (bitset<32>(a31) << 31);
            t.b ^= (bitset<32>(b30) << 30) ^ (bitset<32>(b31) << 31);
            bool found = true;
            REP_R (i, points - 1) {
                if (generate_nth(i, t.x, t.a, t.b) != history[i]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                cerr << "RX = " << t.x << endl;
                cerr << "RA = " << t.a << endl;
                cerr << "RB = " << t.b << endl;
                return t;
            }
        }
    }
    assert (false);
}

template <class Function>
void solve(Function play) {
    vector<uint8_t> history;
    REP (i, points - 1) {
        history.push_back(play(0));
    }
    state_t s = reconstruct(history);
    REP (i, points - 1) {
        generate_destructive(s.x, s.a, s.b);
    }
    while (true) {
        uint8_t guess = generate_destructive(s.x, s.a, s.b);
        play(guess);
    }
}


int main(int argc, char **argv) {
    // args
    assert (argc == 3);
    string host = argv[1];
    int port = stoi(argv[2]);

    // connect
    boost::asio::ip::tcp::iostream stream(host, to_string(port));
    auto readline = [&]() {
        string line;
        getline(stream, line);
        return line;
    };

    if (host != "localhost") { // proof of work
        string line = readline();
        cerr << line << endl;;
        string prefix = line.substr(line.find('\'') + 1, 24);
        cerr << "prefix = " << prefix << endl;
        for (ll i = 0; ; ++ i) {
            string x = prefix;
            ll acc = i;
            REP (j, 5) {
                x += "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[acc % 62];
                acc /= 62;
            }
            uint8_t digest[SHA_DIGEST_LENGTH];
            SHA1(reinterpret_cast<const uint8_t *>(x.c_str()), x.length(), digest);
            if (digest[SHA_DIGEST_LENGTH - 1] != 0xff) continue;
            if (digest[SHA_DIGEST_LENGTH - 2] != 0xff) continue;
            if (digest[SHA_DIGEST_LENGTH - 3] != 0xff) continue;
            if ((digest[SHA_DIGEST_LENGTH - 4] & 0x3) != 0x3) continue;
            cerr << "x = " << x << endl;
            stream << x << endl;
            stream.flush();
            break;
        }
    }

    int current_points = 30;
    auto play = [&](int n) {
        while (readline().find("Guess a number") == string::npos);
        stream << n << '\n'; stream.flush();
        string s; stream >> s;
        cerr << "play(" << n << "): " << s;
        if (s != "Wrong.") cerr << endl;
        if (s == "Congratulations!") {
            current_points += 1;
            if (current_points == points_total) {
                while (stream) {
                    cout << char(stream.get());
                    cout.flush();
                }
                throw runtime_error("");
            }
            return n;
        } else if (s == "Wrong.") {
            current_points -= 1;
            stream >> s; // The
            stream >> s; // number
            stream >> s; // was
            int result; stream >> result;
            cerr << " " << result << endl;
            return result;
        } else if (s == "Your") {
            return -1;
        } else {
            throw runtime_error("");
        }
    };
    solve(play);

    return 0;
}
```
