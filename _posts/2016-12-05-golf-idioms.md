---
category: blog
layout: post
date: "2016-12-05T22:32:26+09:00"
tags: [ "golf" ]
---

# golfテクを4つ紹介する

適当な基準で$4$つ選びました。

## C言語 三項演算子cast

三項演算子の第$2,3$項目の型が一致することを用いてcastできる。

``` c
main(ptr) {
    *ptr; // error: invalid type argument of unary ‘*’ (have ‘int’)
    *(0?"":ptr); // ok
}
```

### 例

<http://golf.shinh.org/reveal.rb?Merge+Digits/nu%28tails%29_1461951633&c> (tailsさん)

``` c
o;main(p,q){for(;~scanf("%ms%s"+o,&p,q);putchar(o?:10))o=*(0?"":bcmp(p,q)>0?p++:q++);}
```

## perl/ruby/python 他言語経由での入力

読み取りに強い言語で入力を受けて処理本体が強い言語でevalすると短くなる場合がある。

### 例

<https://beta.atcoder.jp/contests/atc002/submissions/977052> (%20さん)

``` sh
read N M P;python -c"print pow($N,$P,$M)"
```

参考として、普通に書くと:

``` python
n,m,p=map(int,input().split());print(pow(n,p,m))
```

## bash 空白文字の差の利用

bashにとっては非空白文字だがwcにとっては空白文字であるといった認識の不一致がある文字が存在する。これを使えば`'`や`\`の分を縮めることができる。

### 例

<http://yukicoder.me/submissions/115983>

垂直tab`\v`の例。`tr n \ |wc -w`から$1$byte縮む。

``` sh
$ cat a.sh
tr n 
     |wc -w%

$ xxd a.sh
00000000: 7472 206e 200b 7c77 6320 2d77            tr n .|wc -w
```

## sed等 改行文字の修正

いくらかのサービスでは提出時の改行コードが`\r\n`となる。改行が他の文字で代替できない言語で問題になる。
しかし、(特にAtCoderでのそれは)ブラウザを介さず直接POSTすることで回避できる場合が多い。

つまりHTTP requestをブラウザを介さず発行すればよいため、適当な提出用scriptを借りてくるだけで回避できる。
いったん普通に提出しブラウザのDevelopper toolsのCopy as cURL機能を用いて`curl`コマンドを得て`%0D%0A`を`%0A`に置換して実行するのでもよい。

### 例

-   $47$byte: <https://beta.atcoder.jp/contests/cf16-relay-open/submissions/1003598>
-   $48$byte: <https://beta.atcoder.jp/contests/cf16-relay-open/submissions/1003596>
