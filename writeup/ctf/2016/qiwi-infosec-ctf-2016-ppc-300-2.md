---
layout: post
redirect_from:
  - /blog/2016/11/19/qiwi-infosec-ctf-2016-ppc-300-2/
date: "2016-11-19T01:30:50+09:00"
tags: [ "ctf", "writeup", "qiwi-ctf", "ppc", "brainfuck" ]
---

# Qiwi Infosec CTF 2016: PPC 300_2

再帰的にbrainfuckのコードを出力するbrainfuckのコードが与えられるので実行。最後はpythonが出てきた。
処理系最適化ゲーだと踏んでさあやるぞと思ったのに全然必要なかった。悲しい。

``` sh
$ f=file ; while [ -s $f ] ; do ./a.out $f > $f.result ; f=$f.result ; done

$ cat file.result.result.result.result.result.result.result
import hashlib
class Tolkien:
    def __init__(self):
        self.quote = 'Not all those who wander are lost'
if __name__ == '__main__':
    t = Tolkien()
    print(hashlib.md5(t.quote.encode('utf-8')).hexdigest())

$ python file.result.result.result.result.result.result.result
0084a25c8ec578200fe9152005f767d4
```

まだ本気最適化の処理系書いてないんだよねと言いながら書いた雛形は以下。次の機会にはちゃんと本気を出したい。

``` c++
#include <cstdio>
#include <string>
#include <deque>
#include <map>
#include <stack>
#include <cassert>
using namespace std;

string code;
map<int, int> jump;
void load(string const & path) {
    FILE *fh = fopen(path.c_str(), "r");
    stack<int> loop;
    for (char c; (c = fgetc(fh)) != EOF; ) {
        switch (c) {
            case '+': case '-': case '<': case '>': case ',': case '.':
                break;
            case '[':
                loop.push(code.size());
                break;
            case ']': {
                assert (not loop.empty());
                int i = loop.top(); loop.pop();
                int j = code.size();
                jump[i] = j;
                jump[j] = i;
            }
                break;
            default:
                c = 0;
        }
        if (c) code += c;
    }
    fclose(fh);
    assert (loop.empty());
}

typedef uint8_t cell_t;
void execute() {
    deque<cell_t> mem(30000);
    int ip = 0, dp = 0;
    for (; ip < code.size(); ++ ip) {
        switch (code[ip]) {
            case '+': ++ mem[dp]; break;
            case '-': -- mem[dp]; break;
            case '>': ++ dp; if (mem.size() <= dp) mem.resize(2 * mem.size()); break;
            case '<': -- dp; while (dp < 0) { mem.emplace_front(); dp += 1; } break;
            case ',': mem[dp] = getchar(); break;
            case '.': putchar(mem[dp]); break;
            case '[': if (not mem[dp]) ip = jump[ip]; break;
            case ']': if (    mem[dp]) ip = jump[ip]; break;
        }
    }
}

int main(int argc, char **argv) {
    assert (argc == 2);
    load(argv[1]);
    execute();
    return 0;
}
```
