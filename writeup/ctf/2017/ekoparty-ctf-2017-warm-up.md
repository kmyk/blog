---
layout: post
alias: "/blog/2017/09/20/ekoparty-ctf-2017-warm-up/"
date: "2017-09-20T20:38:47+09:00"
title: "EKOPARTY CTF 2017: Warm Up"
tags: [ "ctf", "writeup", "rev", "ekoparty-ctf", "angr" ]
---

rev苦手勢なのでangrでなんとかなる問題しか倒せない。

## solution

読むと次のようになってる。angrすればすぐでる。

``` asm
get_input:
  4009ae:	55                   	push   rbp
  4009af:	48 89 e5             	mov    rbp,rsp
  4009b2:	bf 04 17 4a 00       	mov    edi,0x4a1704  # "Enter your values: "
  4009b7:	b8 00 00 00 00       	mov    eax,0x0
  4009bc:	e8 ef ed 00 00       	call   0x40f7b0 # puts
  4009c1:	be 60 cd 6c 00       	mov    esi,0x6ccd60  # buf
  4009c6:	bf 18 17 4a 00       	mov    edi,0x4a1718  # "%s"
  4009cb:	b8 00 00 00 00       	mov    eax,0x0
  4009d0:	e8 0b ef 00 00       	call   0x40f8e0 # scanf
  4009d5:	90                   	nop
  4009d6:	5d                   	pop    rbp
  4009d7:	c3                   	ret    #=> main 0x400e6d
```

``` asm
check_input:
  4009d8:	55                   	push   rbp
  4009d9:	48 89 e5             	mov    rbp,rsp
  4009dc:	b8 62 cd 6c 00       	mov    eax,0x6ccd62
  4009e1:	0f b6 10             	movzx  edx,BYTE PTR [rax]
  4009e4:	b8 1b 17 4a 00       	mov    eax,0x4a171b
  ...
  400c6c:	bf 41 17 4a 00       	mov    edi,0x4a1741  # "valid!"
  400c71:	e8 3a f5 00 00       	call   0x4101b0  # puts
  400c76:	b8 01 00 00 00       	mov    eax,0x1  # success
  400c7b:	e9 dd 00 00 00       	jmp    0x400d5d
  400c80:	b8 00 00 00 00       	mov    eax,0x0  # failure
  400c85:	e9 d3 00 00 00       	jmp    0x400d5d
  ...
  400d51:	b8 00 00 00 00       	mov    eax,0x0
  400d56:	eb 05                	jmp    0x400d5d
  400d58:	b8 00 00 00 00       	mov    eax,0x0
  400d5d:	5d                   	pop    rbp
  400d5e:	c3                   	ret    
```

``` asm
main:
  400e5f:	55                   	push   rbp
  400e60:	48 89 e5             	mov    rbp,rsp
  400e63:	b8 00 00 00 00       	mov    eax,0x0
  400e68:	e8 41 fb ff ff       	call   0x4009ae # get_input
  400e6d:	b8 00 00 00 00       	mov    eax,0x0
  400e72:	e8 d8 ff ff ff       	call   0x400e4f # xxx_check_input
  400e77:	5d                   	pop    rbp
  400e78:	c3                   	ret    
  400e79:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
```

## implementation

``` python
#!/usr/bin/env python2
import angr
import claripy

binary = './warmup'
check_function = 0x4009d8
valid = 0x400c6c
invalid = 0x400d5d
buf = 0x6ccd60

p = angr.Project(binary, load_options={ 'auto_load_libs': False })
state = p.factory.entry_state(addr=check_function)

len_flag = 64
flag = claripy.BVS('flag', 8 * len_flag)
state.memory.store(buf, flag)

pathgroup = p.factory.path_group(state)
pathgroup.explore(find=valid, avoid=invalid)
for path in pathgroup.found:
    print repr(path.state.se.any_str(flag))
```
