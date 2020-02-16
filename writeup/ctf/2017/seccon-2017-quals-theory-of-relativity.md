---
layout: post
alias: "/blog/2017/12/10/seccon-2017-quals-theory-of-relativity/"
date: "2017-12-10T15:19:20+09:00"
tags: [ "ctf", "writeup", "seccon", "seccon-quals", "web", "interpreter" ]
"target_url": [ "https://ctftime.org/event/512/" ]
---

# SECCON 2017 Online CTF: Theory of Relativity

## problem

An interpreter of a simple language and the web-interface are given.
Submit a code which runs more than $100$sec (but the execution time limit is $20$sec).

## solution

Print `user 100.001s` to the stderr, using error messages.
The server executes `bash -c "time timeout 20 python %s %s" 1>%s 2>%s` and retrieve the elapsed time using the regex `^user\t([0-9]+m)?([0-9]+\.[0-9]{3}s)$`.

## implementation

```
ls r0, '\nuser\t0m100.001s\n'
li r1, 42
add r0, r0, r1
```
