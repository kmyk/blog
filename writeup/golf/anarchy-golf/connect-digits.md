---
layout: post
redirect_from:
  - /blog/2016/06/15/anagol-connect-digits/
date: 2016-06-15T22:20:15+09:00
tags: [ "golf", "writeup", "anagol", "anarchy-golf", "sed", "brainfuck", "perl", "c" ]
"target_url": [ "http://golf.shinh.org/p.rb?Connect+Digits" ]
---

# Anarchy Golf 954. Connect Digits

公開直後に縮まなくなるまでやってそのまま忘れていたら、提出した全ての言語で最下位になっていました。悲しい。

## brainfuck

<http://golf.shinh.org/reveal.rb?Connect+Digits/kimiyuki_1465065337>

### 私 74byte

``` brainfuck
#!/usr/bin/env bfi
,.<,+[
    *b&1 a
    -<+>>
    0 1 b *a 0
    [>+<-<[-<<]<[+<<]>>>>]
    a~b&1 b~a *0 a
    +
    <[>[-]>+.<<-]
    <-[>>[-]>-.<<<-]
    >>[>.<-]
    ,+
    *c&1 b
]
```

$(b, a)$引き算して$((a\dot{-}b)+1, b\dot{-}a, 0, a)$のようにして、$a$を$b$に変化させながら出力。

### mitchsさん 56byte

<http://golf.shinh.org/reveal.rb?Connect+Digits/mitchs_1464799809>

``` brainfuck
,+[-
    a a&1 0 *b
    [
        >+>++[-<<]<
        a a\k 0 *b\k k k
        [+.<<]>>[>>]>
    ]
    a a&1\b 0 *0 b b
    <<[-[-[<-.>-]]]
    >>>.>+>>
    b 0 0 0 b b&1 0 *0
,+]
```

同様に引き算(limited subtraction)をするのだが、引きすぎる場合は引きながら出力している。たしかにどうせ引く対象が$0$かどうかで場合分けが入っているので、出力はそこに吸収させられる。賢い。

## sed

### 私 108byte

<http://golf.shinh.org/reveal.rb?Connect+Digits/kimiyuki_1464772487>

``` sed
s/^/I/
:
s/I\(.\)\(.\)/\1<0123456789 9876543210>\2/
s/\(.\)<.*\1\(\w*\)\(.\).*>\3/\1\2I\3/
s/<.*>/I/
t
s/I//
```

前から指示子`I`で1文字ずつ見ていって、`x<0123456789 987654321>y`を作って、`x`や`y`をcaptureして無理矢理該当部分を切り出した。

### mitchsさん 69byte

<http://golf.shinh.org/reveal.rb?Connect+Digits/mitchs_1464924624>

``` sed
s/./&<0123456789@9876543210&& &/g
s/<\(\S\)*\(\(\w\)*\)\S* \1\3*/\2/g
```

隣接する`ab`に対し、`<0123456789@9876543210aa ab`という形を作り、`a\w*b`にmatchする`\w*b`で置き換え。
先頭も末尾もいい感じになっている。

## c

私のそれは97byteとかいう酷さでした。

### mitchsさん + tailsさん 54byte

<http://golf.shinh.org/reveal.rb?Connect+Digits/mitchs+%28tails%29_1465935599>

``` c
t;main(c){while(read(-t%c,&c,1))putchar(t-=c/~t|t>c);}
```

``` c
t;
main(c) {
    while (read((-t)%c, &c, 1))
        putchar(t -= (c/~t) | (t>c));
}
```

`t`にはひとつ前の文字が入り、`c`には現在の文字が入る。
`ssize_t read(int fd, void *buf, size_t count);`。
`(-t)%c`は、`t`が`c`の倍数なら$0$で`STDIN_FILENO`、そうでなければ負値なので全体で`nop`。
little endianで$1$文字読むので、普通に$48 \dots 58$の整数として`c`に入る。
`t`から引いている式の`|`は結合順位の問題を除けば`+`で置き換えてよい。
`~t`は`-(t+1)`なので、この場合`t<c?-1:0`や`-(t<c)`と同じように動く。
`c`は`t`に近付く方向に動いていき、一致したあと`-t%c`が$0$になり次の文字を読む。

## perl

私の提出は69byteでした。

### teebeeさん 43byte

<http://golf.shinh.org/reveal.rb?Connect+Digits/teebee_1464762573>

``` perl
print$_+=~$_?$&<=>$_:$&until/$&/&&getc!~/./
```

``` perl
print($_ += (~ $_ ? ($& <=> $_) : $&)) until (/$&/ && (getc !~ /./))
```

`$_`にはひとつ前の文字が入り、`$&`には現在の文字が入る。
まず最初に`getc !~ /./`が走って、読んだ文字を`$&`にcaptureする。
`!~`はpattern match演算子の否定形。
初回なので`$_`が空であり、自分自身とのmatch `~ $_`は失敗し、整数`$_`に`$&`が代入される。
`/$&/`が成功してもう一度`getc`が発生。ここで初期化終了。
`/$&/`が成功するまで、`$_`を`$&`に近付けていく。
宇宙船演算子`<=>`は引き算の結果を$[-1, 1]$にclampして返す比較用の演算子。
一致すると再度`getc`。
