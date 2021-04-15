---
layout: post
redirect_from:
  - /writeup/ctf/2017/codegate-2017-prequals-angrybird/
  - /blog/2017/02/11/codegate-2017-prequals-angrybird/
date: "2017-02-11T09:23:17+09:00"
tags: [ "ctf", "writeup", "rev", "angr" ]
---

# Codegate 2017 prequals: angrybird

## solution

edit the binary + angr.

[radare2](https://github.com/radare/radare2) is useful to edit binaries.

``` asm
$ diff <(objdump -d -M intel angrybird) <(objdump -d -M intel angrybird.modified)
2c2
< angrybird:     file format elf64-x86-64
---

# Codegate 2017 prequals: angrybird
> angrybird.modified:     file format elf64-x86-64
152,154c152,160
<   40071a:     67 8b 04 24             mov    eax,DWORD PTR [esp]
<   40071e:     83 f8 00                cmp    eax,0x0
<   400721:     0f 85 b9 fe ff ff       jne    4005e0 <exit@plt>
---

# Codegate 2017 prequals: angrybird
>   40071a:     b8 00 00 00 00          mov    eax,0x0
>   40071f:     90                      nop
>   400720:     90                      nop
>   400721:     90                      nop
>   400722:     90                      nop
>   400723:     90                      nop
>   400724:     90                      nop
>   400725:     90                      nop
>   400726:     90                      nop
163,167c169,173
<   40073a:     48 8b 45 f8             mov    rax,QWORD PTR [rbp-0x8]
<   40073e:     ba 05 00 00 00          mov    edx,0x5
<   400743:     be 8e 50 40 00          mov    esi,0x40508e
<   400748:     48 89 c7                mov    rdi,rax
<   40074b:     e8 30 fe ff ff          call   400580 <strncmp@plt>
---

# Codegate 2017 prequals: angrybird
>   40073a:     bf 38 60 60 00          mov    edi,0x606038
>   40073f:     be 8e 50 40 00          mov    esi,0x40508e
>   400744:     b9 05 00 00 00          mov    ecx,0x5
>   400749:     f3 a4                   rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]
>   40074b:     b8 00 00 00 00          mov    eax,0x0
183c189,194
<   40077b:     0f 84 5f fe ff ff       je     4005e0 <exit@plt>
---

# Codegate 2017 prequals: angrybird
>   40077b:     90                      nop
>   40077c:     90                      nop
>   40077d:     90                      nop
>   40077e:     90                      nop
>   40077f:     90                      nop
>   400780:     90                      nop
```

``` python
#!/usr/bin/env python2
import angr # angr-6.7.1.31
p = angr.Project('./angrybird.modified')
state = p.factory.entry_state()
goal = 0x404fdb
pathgroup = p.factory.path_group(state)
pathgroup.explore(find=goal)
for path in pathgroup.found:
    print repr(path.state.posix.dumps(0))
```

``` sh
(angr) $ ./a.py
WARNING | 2017-02-10 18:56:15,305 | simuvex.plugins.symbolic_memory | Concretizing symbolic length. Much sad; think about implementing.
'Im_so_cute&pretty_:)\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\n\n\n\n\n\n\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
./a.py  37.70s user 1.03s system 99% cpu 38.787 total
```
