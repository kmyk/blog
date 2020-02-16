---
layout: post
alias: "/blog/2016/10/10/hitcon-ctf-2016-quals-regexpert/"
date: "2016-10-10T23:03:41+09:00"
tags: [ "ctf", "writeup", "misc", "regex", "ruby", "palindrome", "context-free-grammaer", "context-sensitive-grammar" ]
---

# HITCON QUALS CTF 2016: RegExpert

I like this.
I didn't know about context-sensitive in regex.

It seemed the regex engine was Oniguruma/ruby.

``` ruby
$ nc 52.69.125.71 2171
Hi! We want to hire some TRUE regular expression hackers to write firewall rules.
So here are five interview questions for you, good luck!
Note: After CVE-2015-4410, we reject everything contains newline, so you can just safely use ^ and $ here.

================= [SQL] =================
Please match string that contains "select" as a case insensitive subsequence.
(?i)s.*e.*l.*e.*c.*t
Running on test #885...Accepted :)

=============== [a^nb^n] ================
Yes, we know it is a classical example of context free grammer.
^(a\g<1>?b)$
Running on test #370...Accepted :)

================= [x^p] =================
A prime is a natural number greater than 1 that has no positive divisors other than 1 and itself.
^(?!(xx+)\1+$)xx+$
Running on test #304...Accepted :)

============= [Palindrome] ==============
Both "QQ" and "TAT" are palindromes, but "PPAP" is not.
^((.)\g<1>\k<2+0>|.?)$
Running on test #799...Accepted :)

============== [a^nb^nc^n] ==============
Is CFG too easy for you? How about some context SENSITIVE grammer?
^(?=(a\g<1>b|)c)a*(b\g<2>c|)$
Running on test #504...Accepted :)

Congratz! Here is your singing bonus:
hitcon{The pumping lemma is a lie, just like the cake}
```
