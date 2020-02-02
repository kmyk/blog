---
layout: post
alias: "/blog/2015/12/06/seccon-2015-online-command-line-quiz/"
title: "SECCON 2015 オンライン予選 Command-Line Quiz"
date: 2015-12-06T20:32:40+09:00
tags: [ "ctf", "writeup", "seccon", "quiz", "pwn" ]
---

気付かなければ気付かない系のパズル。unix系のosを常用している人で、勘が良いか時間をつぎ込むかすれば解ける。

<!-- more -->

## [Unknown 100. Command-Line Quiz](https://github.com/SECCON/SECCON2015_online_CTF/blob/master/Unknown/100_Command-Line%20Quiz/question.txt)

### 問題

>   telnet caitsith.pwn.seccon.jp  
>   User:root  
>   Password:seccon  
>   すべての \*.txt ファイルを読め

### 解法

まず、指定された通りに

``` sh
$ telnet caitsith.pwn.seccon.jp
CaitSith login: root
Password: seccon
```

としてloginする。

するとcurrent directoryを見ると、`flags.txt`, `stage{1..5}.txt`が存在する。

``` sh
$ ls
bin         etc         init        linuxrc     sbin        stage2.txt  stage4.txt  tmp
dev         flags.txt   lib         proc        stage1.txt  stage3.txt  stage5.txt  usr
```

もちろんここで`flags.txt`を見ようとしても、

``` sh
$ cat flags.txt
cat: can't open '/flags.txt': Operation not permitted
```

と言われ、見れない。`stage{2..5}.txt`は見れないが、唯一`stage1.txt`は見れて、

``` sh
$ cat stage1.txt
What command do you use when you want to read only top lines of a text file?

Set your answer to environment variable named stage1 and execute a shell.

 $ stage1=$your_answer_here sh

 If your answer is what I meant, you will be able to access stage2.txt file.
```

となる。指示に従い、

``` sh
$ stage1=head sh
```

とすると、`stage2.txt`が見れるようになる(`stage1.txt`は見れなくなる)。以降同様にして、

``` sh
$ stage2=tail sh
$ stage3=grep sh
$ stage4=awk  sh
```

とすれば、`stage5.txt`が見れるようになる。

``` sh
$ cat stage5.txt 
OK. You reached the final stage. The flag word is in flags.txt file.

flags.txt can be read by only one specific program which is available
in this server. The program for reading flags.txt is one of commands
you can use for processing a text file. Please find it. Good luck. ;-)
```

しかし、`stage5.txt`の指定はそれ以前のものと形式が違う。
とりあえずここまでを`expect` scriptとしてまとめると以下のようになる。

``` sh
#!/usr/bin/expect
spawn telnet caitsith.pwn.seccon.jp
expect "CaitSith login: "
send "root\n"
expect "Password: "
send "seccon\n"
send "stage1=head sh\n"
send "stage2=tail sh\n"
send "stage3=grep sh\n"
send "stage4=awk  sh\n"
interact
```

さて`stage5.txt`であるが、結論だけ言えば、文中で指示されているプログラムとは`sed`であり、以下のようにすれば中身が見える。

``` sh
$ sed '' flags.txt
OK. You have read all .txt files. The flag word is shown below.

SECCON{CaitSith@AQUA}
```

`sed`でのみ`flags.txt`にアクセスできるので、`sed`に`flags.txt`をそのまま出力させればよい。

``` sh
$ sed --help
Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...
...
```

sed scriptとして空文字列``、つまり何も加工せずそのまま出力するプログラム、を与え、その入力として`flags.txt`を指定すればflagが見える。
本番は`s/./&/g`とかした気がするが、やっていることは同じ。

### 試行錯誤

`sed`からなら`flags.txt`が読めるということに気付くまでに、非常に色々なことを試した。

-   `head`や`tail`で`flags.txt`を開こうとはした。`sed`は漏らしていた
-   `/bin` `/sbin` `/usr/bin` `/usr/sbin` にある全てのバイナリに関して、`$ stage5=XXX sh`を実行
-   バイナリのinodeが全て一致しているという話を聞き、busyboxだということが判明。これを調べる
-   busyboxは、呼び出されたときの自身のファイル名`$0`の値で振舞いを変える。`ln -s /bin/cat /tmp/busybox`などとすれば、busyboxそのものが触れるので、色々試す
-   `which is available in this server`とは言われているが、存在するとは言われていないので、busyboxが対応しているがサーバに存在しないバイナリを探したりした
-   `ps`で他の参加者の実行しているコマンドを見て、ヒントを得ようとした
