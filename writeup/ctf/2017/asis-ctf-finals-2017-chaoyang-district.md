---
layout: post
alias: "/blog/2017/09/11/asis-ctf-finals-2017-chaoyang-district/"
date: "2017-09-11T08:09:47+09:00"
tags: [ "ctf", "writeup", "ppc", "asis-ctf", "othello" ]
---

# ASIS CTF Finals 2017: Chaoyang District

## problem

```
$ nc 178.62.22.245 32145
Turn: Ai
Black Score: 2
White Score: 2

  a b c d e f g h 
1 ................1
2 ................2
3 ......MM........3
4 ....MMWWBB......4
5 ......BBWWMM....5
6 ........MM......6
7 ................7
8 ................8
  a b c d e f g h 


Your goal is to win 50 games consecutively in a row!

Turn: Player
Black Score: 4
White Score: 1

  a b c d e f g h 
1 ................1
2 ................2
3 ....MM..MM......3
4 ....BBBBBB......4
5 ....MMBBWW......5
6 ................6
7 ................7
8 ................8
  a b c d e f g h 


Your goal is to win 50 games consecutively in a row!
Where to move? (ex- a1, c2, d3) 
```

1.  The AI cheats sometimes.
2.  The game ends suddenly.
    -   You cannot use usual solvers, because strong AI gets few stones at the midgame.

## solution

Just write an AI.

## note

-   solver
    -   結局使わなかったが
        -   問題見てothelloだなあと思ったらとりあえず強いsolver持ってきてしまいませんか
    -   Zebra
        -   <http://radagast.se/othello/zebra.html>
        -   古くて動かせなかった
    -   Edax
        -   <https://code.google.com/archive/p/edax-reversi/> から `edax.4-3.zip`
        -   `/usr/lib64/llvm/LLVMgold.so` と言われるのは適当に symbolic linkを張る
-   protocol
    -   othelloはそれ専用のprotocolでデファクトなのがないっぽい？
    -   GTP (go text protocol) が小さくて綺麗な気がする
        -   今回は `setboard` 的なのが必要で使えなかった
        -   <https://www.lysator.liu.se/~gunnar/gtp/gtp2-spec-draft2/gtp2-spec.html>
-   bitboard楽しい

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='178.62.22.245')
parser.add_argument('port', nargs='?', default=32145, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level

p = remote(args.host, args.port)
def readboard():
    game = {}
    p.recvuntil('Turn: ')
    game['turn'] = p.recvline().rstrip()
    p.recvuntil('Black Score: ')
    game['black_score'] = int(p.recvline())
    p.recvuntil('White Score: ')
    game['white_score'] = int(p.recvline())
    assert p.recvline().strip() == ''
    assert p.recvline().rstrip() == '  a b c d e f g h'
    game['board'] = [ [ None for _ in range(8) ] for _ in range(8) ]
    for y in range(8):
        line = p.recvline().rstrip()
        assert line.startswith('%d ' % (y + 1))
        assert line.endswith('%d' % (y + 1))
        line = line[2 : -1]
        for x in range(8):
            assert line[2 * x] == line[2 * x + 1]
            if line[2 * x] == 'W':
                game['board'][y][x] = 'W'
            elif line[2 * x] == 'B':
                game['board'][y][x] = 'B'
            else:
                assert line[2 * x] in '.M'
    assert p.recvline().rstrip() == '  a b c d e f g h'
    return game
def telmove(vertex):
    p.sendlineafter('Where to move? (ex- a1, c2, d3) ', vertex)

def vertex_to_indices(vertex):
    x = 'abcdefgh'.index(vertex[0].lower())
    y = '12345678'.index(vertex[1])
    return y, x
def indices_to_vertex(y, x):
    return 'abcdefgh'[x] + '12345678'[y]
def get_move(new, old):
    for y in range(8):
        for x in range(8):
            if not old['board'][y][x] and new['board'][y][x]:
                return indices_to_vertex(y, x)
def initial_game():
    game = {}
    game['turn'] = 'Ai'
    game['black_score'] = 2
    game['white_score'] = 2
    game['board'] = [ [ None for _ in range(8) ] for _ in range(8) ]
    game['board'][3][3] = 'W'
    game['board'][3][4] = 'B'
    game['board'][4][3] = 'B'
    game['board'][4][4] = 'W'
    return game
def format_game(game):
    s = ''
    s += 'Trun: %s\n' % game['turn']
    s += '  A B C D E F G H\n'
    for y in range(8):
        s += '%d ' % (y + 1)
        for x in range(8):
            c = '.'
            if game['board'][y][x] == 'B':
                c = '*'
            elif game['board'][y][x] == 'W':
                c = 'O'
            s += '%s ' % c
        s += '%d\n' % (y + 1)
    s += '  A B C D E F G H\n'
    return s

class Solver(object):
    def __init__(self):
        self.proc = process('./a.out')
    def __enter__(self):
        self.proc.__enter__()
        return self
    def __exit__(self, exc_type, exc_value, traceback):
        self.proc.__exit__(exc_type, exc_value, traceback)
    def play(self, color, vertex):
        self.proc.sendline('play %s %s' % (color, vertex))
        self.proc.recvuntil('= ')
        self.proc.recvline()
    def genmove(self, color):
        self.proc.sendline('genmove %s' % color)
        self.proc.recvuntil('= ')
        return self.proc.recvline().rstrip().lower()
    def showboard(self):
        self.proc.sendline('showboard')
        self.proc.recvuntil('= ')
        board = {}
        board['format'] = self.proc.recvuntil('8\n  A B C D E F G H\n')
        board['parse'] = [ [ None for _ in range(8) ] for _ in range(8) ]
        for y in range(8):
            for x in range(8):
                c = board['format'].splitlines()[1 + y][2 + 2 * x]
                if c == '*':
                    board['parse'][y][x] = 'B'
                elif c == 'O':
                    board['parse'][y][x] = 'W'
        return board
    def setboard(self, board):
        s = ''
        for y in range(8):
            for x in range(8):
                c = '-'
                if board[y][x] == 'B':
                    c = '*'
                elif board[y][x] == 'W':
                    c = 'O'
                s += c
        self.proc.sendline('setboard %s' % s)
        self.proc.recvuntil('= ')

with Solver() as solver:
    while True:
        game = readboard()
        log.info(format_game(game))

        if game['turn'] == 'Ai':
            pass

        elif game['turn'] == 'Player':
            solver.setboard(game['board'])
            vertex = solver.genmove('white')
            log.info('Player: %s', vertex)
            log.info(solver.showboard()['format'])
            telmove(vertex)
```

``` c++
#include <algorithm>
#include <cassert>
#include <iostream>
#include <sstream>
#include <tuple>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

typedef uint64_t bitboard_t;

bitboard_t to_bitboard(int y, int x) {
    assert(0 <= y && y < 8);
    assert(0 <= x && x < 8);
    return 1ull << (y * 8 + x);
}
pair<int, int> from_bitboard(bitboard_t t) {
    repeat (y, 8) {
        repeat (x, 8) {
            if (to_bitboard(y, x) & t) {
                return { y, x };
            }
        }
    }
    return { -1, - 1 };
}

template <typename Shift>
bitboard_t get_mobility_one_direction(bitboard_t black, bitboard_t white, bitboard_t mask, Shift shift) {
    bitboard_t w = white & mask;
    bitboard_t t = w & shift(black);
    t |= w & shift(t);
    t |= w & shift(t);
    t |= w & shift(t);
    t |= w & shift(t);
    t |= w & shift(t);
    bitboard_t blank = ~ (black | white);
    return blank & shift(t);
}
bitboard_t get_mobility(bitboard_t black, bitboard_t white) {
    bitboard_t mobility = 0;
    mobility |= get_mobility_one_direction(black, white, 0x7e7e7e7e7e7e7e7e, [](bitboard_t t) { return t >> 1; }); // right
    mobility |= get_mobility_one_direction(black, white, 0x007e7e7e7e7e7e00, [](bitboard_t t) { return t << 7; }); // up right
    mobility |= get_mobility_one_direction(black, white, 0x00ffffffffffff00, [](bitboard_t t) { return t << 8; }); // up
    mobility |= get_mobility_one_direction(black, white, 0x007e7e7e7e7e7e00, [](bitboard_t t) { return t << 9; }); // up left
    mobility |= get_mobility_one_direction(black, white, 0x7e7e7e7e7e7e7e7e, [](bitboard_t t) { return t << 1; }); // left
    mobility |= get_mobility_one_direction(black, white, 0x007e7e7e7e7e7e00, [](bitboard_t t) { return t >> 7; }); // down left
    mobility |= get_mobility_one_direction(black, white, 0x00ffffffffffff00, [](bitboard_t t) { return t >> 8; }); // down
    mobility |= get_mobility_one_direction(black, white, 0x007e7e7e7e7e7e00, [](bitboard_t t) { return t >> 9; }); // down right
    return mobility;
}

template <typename Shift>
inline bitboard_t get_reversed_one_direction(bitboard_t black, bitboard_t white, bitboard_t black_move, bitboard_t mask, Shift shift) {
    bitboard_t wh = white & mask;
    bitboard_t m1 = shift(black_move);
    bitboard_t m2, m3, m4, m5, m6;
    bitboard_t rev = 0;
    if ( (m1 & wh) != 0 ) {
        if ( ((m2 = shift(m1)) & wh) == 0 ) {
            if ( (m2 & black) != 0 ) rev |= m1;
        } else if ( ((m3 = shift(m2)) & wh) == 0 ) {
            if ( (m3 & black) != 0 ) rev |= m1 | m2;
        } else if ( ((m4 = shift(m3)) & wh) == 0 ) {
            if ( (m4 & black) != 0 ) rev |= m1 | m2 | m3;
        } else if ( ((m5 = shift(m4)) & wh) == 0 ) {
            if ( (m5 & black) != 0 ) rev |= m1 | m2 | m3 | m4;
        } else if ( ((m6 = shift(m5)) & wh) == 0 ) {
            if ( (m6 & black) != 0 ) rev |= m1 | m2 | m3 | m4 | m5;
        } else {
            if ( (shift(m6) & black) != 0 ) rev |= m1 | m2 | m3 | m4 | m5 | m6;
        }
    }
    return rev;
}
bitboard_t get_reversed(bitboard_t black, bitboard_t white, bitboard_t black_move) {
    bitboard_t reversed = 0;
    reversed |= get_reversed_one_direction(black, white, black_move, 0x7f7f7f7f7f7f7f7f, [](bitboard_t t) { return t >> 1; }); // right
    reversed |= get_reversed_one_direction(black, white, black_move, 0x7f7f7f7f7f7f7f7f, [](bitboard_t t) { return t << 7; }); // up right
    reversed |= get_reversed_one_direction(black, white, black_move, 0xffffffffffffffff, [](bitboard_t t) { return t << 8; }); // up
    reversed |= get_reversed_one_direction(black, white, black_move, 0xfefefefefefefefe, [](bitboard_t t) { return t << 9; }); // up left
    reversed |= get_reversed_one_direction(black, white, black_move, 0xfefefefefefefefe, [](bitboard_t t) { return t << 1; }); // left
    reversed |= get_reversed_one_direction(black, white, black_move, 0xfefefefefefefefe, [](bitboard_t t) { return t >> 7; }); // down left
    reversed |= get_reversed_one_direction(black, white, black_move, 0xffffffffffffffff, [](bitboard_t t) { return t >> 8; }); // down
    reversed |= get_reversed_one_direction(black, white, black_move, 0x7f7f7f7f7f7f7f7f, [](bitboard_t t) { return t >> 9; }); // down right
    return reversed;
}

int bitboard_popcount(bitboard_t t) {
    return __builtin_popcountll(t);
}

template <typename F>
int negaalpha_search(bitboard_t black, bitboard_t white, int alpha, int beta, int depth, F evaluate) {
    if (depth == 0) {
        return evaluate(black, white);
    } else {
        bitboard_t y = get_mobility(black, white);
        for (bitboard_t x = y & - y; x; x = y & (~ y + (x << 1))) { // x is a singleton and a subset of y
            bitboard_t reversed = get_reversed(black, white, x);
            setmax(alpha, - negaalpha_search(white | reversed, black | reversed | x, - beta, - alpha, depth - 1, evaluate));
            if (alpha >= beta) break;
        }
        return alpha;
    }
}
template <typename F>
bitboard_t negaalpha_move(bitboard_t black, bitboard_t white, int alpha, int beta, int depth, F evaluate) {
    assert (depth != 0);
    bitboard_t m = 0;
    bitboard_t y = get_mobility(black, white);
    for (bitboard_t x = y & - y; x; x = y & (~ y + (x << 1))) { // x is a singleton and a subset of y
        bitboard_t reversed = get_reversed(black, white, x);
        int next_alpha = - negaalpha_search(white | reversed, black | reversed | x, - beta, - alpha, depth - 1, evaluate);
        if (alpha < next_alpha) {
            alpha = next_alpha;
            m = x;
        }
        if (alpha >= beta) break;
    }
    assert (m);
    return m;
}

string show_bitboard(bitboard_t black, bitboard_t white, bitboard_t dot = 0) {
    ostringstream oss;
    oss << "  A B C D E F G H" << endl;
    repeat (y, 8) {
        oss << (y + 1) << ' ';
        repeat (x, 8) {
            char c = '-';
            if (black & to_bitboard(y, x)) {
                c = '*';
            } else if (white & to_bitboard(y, x)) {
                c = 'O';
            } else if (dot & to_bitboard(y, x)) {
                c = '.';
            }
            oss << c << ' ';
        }
        oss << (y + 1) << endl;
    }
    oss << "  A B C D E F G H" << endl;
    return oss.str();
}
const bitboard_t initial_black = to_bitboard(3, 4) | to_bitboard(4, 3);
const bitboard_t initial_white = to_bitboard(3, 3) | to_bitboard(4, 4);

pair<int, int> read_vertex(string s) {
    if (not (s.length() == 2)) return { -1, -1 };
    s[0] = tolower(s[0]);
    if (not ('a' <= s[0] and s[0] <= 'h')) return { -1, -1 };
    if (not ('1' <= s[1] and s[1] <= '8')) return { -1, -1 };
    return { s[1] - '1', s[0] - 'a' };
}
string show_vertex(int y, int x) {
    return string() + "abcdefgh"[x] + "12345678"[y];
}

const bitboard_t bitboard_corner
    = to_bitboard(0, 0)
    | to_bitboard(0, 7)
    | to_bitboard(7, 0)
    | to_bitboard(7, 7);
const bitboard_t bitboard_around_corner
    = to_bitboard(0, 1)
    | to_bitboard(1, 0)
    | to_bitboard(1, 1)
    | to_bitboard(0, 6)
    | to_bitboard(1, 7)
    | to_bitboard(1, 6)
    | to_bitboard(7, 1)
    | to_bitboard(6, 0)
    | to_bitboard(6, 1)
    | to_bitboard(7, 6)
    | to_bitboard(6, 7)
    | to_bitboard(6, 6);
bitboard_t genmove(bitboard_t black, bitboard_t white) {
    constexpr int inf = 1e9+7;
    return negaalpha_move(black, white, - inf, inf, 8, [](bitboard_t black, bitboard_t white) {
        int score = 0;
        score += bitboard_popcount(black) * 1000;
        score -= bitboard_popcount(white) * 1000;
        score += bitboard_popcount(black & bitboard_corner) * 50000;
        score -= bitboard_popcount(white & bitboard_corner) * 50000;
        score -= bitboard_popcount(black & bitboard_around_corner) * 10000;
        score += bitboard_popcount(white & bitboard_around_corner) * 10000;
        score += bitboard_popcount(get_mobility(black, white)) * 1000;
        score -= bitboard_popcount(get_mobility(white, black)) * 1000;
        return score;
    });
}

bool swap_by_color_string(bitboard_t & black, bitboard_t & white, string color) {
    if (color == "b" or color == "black") {
        // pass
        return true;
    } else if (color == "w" or color == "white") {
        swap(black, white);
        return true;
    } else {
        return false;
    }
}

int main() {
    bitboard_t black = initial_black;
    bitboard_t white = initial_white;
    while (true) {
        cout.flush();
        istringstream iss; {
            string line; getline(cin, line);
            iss = istringstream(line);
        }
        string command; iss >> command;

        // play color vertex
        if (command == "play") {
            string color; iss >> color;
            if (not swap_by_color_string(black, white, color)) {
                cout << "? syntax error (wrong color)" << endl;
                continue;
            }
            string vertex; iss >> vertex;
            int y, x; tie(y, x) = read_vertex(vertex);
            if (y == -1 or x == -1) {
                cout << "? syntax error (wrong vertex)" << endl;
                continue;
            }
            bitboard_t m = to_bitboard(y, x);
            if (not (m & get_mobility(black, white))) {
                cout << "? illegal move" << endl;
                continue;
            }
            bitboard_t reversed = get_reversed(black, white, m);
            black ^= reversed | m;
            white ^= reversed;
            swap_by_color_string(black, white, color);
            cout << "= " << endl;

        // genmove color
        } else if (command == "genmove") {
            string color; iss >> color;
            if (not swap_by_color_string(black, white, color)) {
                cout << "? syntax error (wrong color)" << endl;
                continue;
            }
            bitboard_t m = genmove(black, white);
            assert (m & get_mobility(black, white));
            bitboard_t reversed = get_reversed(black, white, m);
            black ^= reversed | m;
            white ^= reversed;
            swap_by_color_string(black, white, color);
            int y, x; tie(y, x) = from_bitboard(m);
            cout << "= " << show_vertex(y, x) << endl;

        // showboard
        } else if (command == "showboard") {
            bitboard_t mobility = get_mobility(black, white);
            cout << "= " << show_bitboard(black, white, mobility) << endl;

        // setboard board
        } else if (command == "setboard") {
            string board; iss >> board;
            if (board.size() != 64
                    or count_if(whole(board), [](char c) { return c == '*' or c == 'O' or c == '-'; }) != 64) {
                cout << "? syntax error" << endl;
                continue;
            }
            black = white = 0;
            repeat (y, 8) {
                repeat (x, 8) {
                    char c = board[y * 8 + x];
                    if (c == '*') {
                        black |= to_bitboard(y, x);
                    } else if (c == 'O') {
                        white |= to_bitboard(y, x);
                    } else {
                        assert (c == '-');
                    }
                }
            }
            cout << "= " << endl;

        } else if (command.empty()) {
            // nop
        } else {
            cout << "? unknown command" << endl;
        }
    }
    return 0;
}
```
