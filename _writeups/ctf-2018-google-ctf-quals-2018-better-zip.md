---
redirect_from:
  - /writeup/ctf/2018/google-ctf-quals-2018-better-zip/
layout: post
date: "2018-06-25T11:39+09:00"
tags: [ "ctf", "writeup", "google-ctf", "crypto", "lfsr", "bruteforce" ]
"target_url": [ "https://ctftime.org/event/623" ]
---

# Google Capture The Flag 2018 (Quals): better zip

<!-- {% raw %} -->

## problem

a encrypted `flag.zip` is given. It's made by `better_zip.py`, using [LFSR](https://ja.wikipedia.org/wiki/%E7%B7%9A%E5%BD%A2%E5%B8%B0%E9%82%84%E3%82%B7%E3%83%95%E3%83%88%E3%83%AC%E3%82%B8%E3%82%B9%E3%82%BF).

```
$ unzip -l flag.zip 
Archive:  flag.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    93674  1980-00-00 00:00   flag.png
---------                     -------
    93674                     1 file
```

## solution

1.  guess the header/footer of `flag.png`
2.  bruteforce

LFSR is literally linear in this case and two IVs are known, but the polynomials are not known.
$8$ instances of $20$-bit FLSR are used simultaneously, and first $20$-bit are the same to the IV, you need know first $40$ byte of the png to crack.
This requires a little too much guessing.
However, $20$-bit, for the polynomials, is too small.
You can bruteforce this and filter candidates with IHDR/IEND chunks with these CRC.
This gives the flag after about $1$ hour on my poor laptop.

## implementation

``` python
#!/usr/bin/env python2
from __future__ import print_function

import binascii
import hashlib
import struct
import subprocess
import sys

from better_zip import BitStream, LFSR, LFSRCipher  # you need to remove the main() part to import

crc32 = lambda x: binascii.crc32(x) % 0x100000000
u16 = lambda x: struct.unpack('<H', x)[0]
u32 = lambda x: struct.unpack('<I', x)[0]
p8_big  = lambda x: struct.pack('>B', x)
p32_big = lambda x: struct.pack('>I', x)

print('[*] open flag.zip')
with open('flag.zip', 'rb') as fh:
    flag_zip = fh.read()

# parse flag.zip
# http://www.tvg.ne.jp/menyukko/cauldron/dtzipformat.html<Paste>
assert flag_zip[0 :][: 4] == 'PK\3\4'
crc = u32(flag_zip[14 :][: 4])
compressed_size = u32(flag_zip[18 :][: 4])
uncompressed_size = u32(flag_zip[22 :][: 4])
file_name_length = u16(flag_zip[26 :][: 2])
assert flag_zip[30 :][: file_name_length] == 'flag.png'
compressed = flag_zip[38 :][: compressed_size]

# parse compressed data
poly_sz = 20
digest_size = hashlib.sha256().digest_size
assert compressed_size == 2 * poly_sz + uncompressed_size + digest_size
crypto_headers = compressed[: 2 * poly_sz]
encrypted_data = compressed[2 * poly_sz :][: uncompressed_size]
encrypted_hash = compressed[2 * poly_sz + uncompressed_size :]
key_iv = crypto_headers[: poly_sz]
cipher_iv = crypto_headers[poly_sz :]
print('[*] key iv =', repr(key_iv))
print('[*] cipher iv =', repr(cipher_iv))
print('[*] crypt(data) =', repr(encrypted_data)[: 200] + '...')
print('[*] crypt(sha256(data)) =', repr(encrypted_hash))

# guess IHDR chunk
ihdr_chunk = ''.join([
    p32_big(13),
    'IHDR',
    p32_big(640),  # width: we can know this only from cipher_iv, without key
    p32_big(0xffff),  # hegith: guessed, 480?
    p8_big(0xff),  # bit depth: guessed
    p8_big(0xff),  # color type: guessed, 2? 6?
    p8_big(0),  # compression method: guessed
    p8_big(0),  # filter method: guessed
    p8_big(0),  # interlace method: guessed
])
ihdr_chunk += '\xff' * 4  # p32_big(crc32(ihdr_chunk[4 :]))

# dispatch to C++
print('[*] exec ./a.out')
sys.stdout.flush()
cipher_iv_stream = BitStream(cipher_iv)
stdin = ''
stdin += ' '.join([ 'ihdr_chunk' ] + [ str(ord(c)) for c in ihdr_chunk ]) + '\n'
for _ in range(8):
    stdin += 'iv ' + str(cipher_iv_stream.get_bits(poly_sz)) + '\n'
stdin += ' '.join([ 'encrypted_data', str(uncompressed_size) ] + [ str(ord(c)) for c in encrypted_data ]) + '\n'
stdin += 'eof\n'
proc = subprocess.Popen([ './a.out' ], stdin=subprocess.PIPE, stderr=sys.stderr)
_, _ = proc.communicate(stdin)
```

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;

uint32_t crc_table[256];
void make_crc_table() {
    REP (i, 256) {
        uint32_t c = i;
        REP (j, 8) {
            c = (c & 1) ? (0xedb88320 ^ (c >> 1)) : (c >> 1);
        }
        crc_table[i] = c;
    }
}
const uint32_t initial_crc32 = 0xffffffff;
uint32_t next_crc32(uint32_t c, char b) {
    return crc_table[(c ^ b) & 0xff] ^ (c >> 8);
}
const uint32_t mask_crc32 = 0xffffffff;
string crc32(string const & s) {
    uint32_t acc = initial_crc32;
    for (char c : s) acc = next_crc32(acc, c);
    acc ^= mask_crc32;
    string t;
    REP_R (i, 4) t += (char)((acc >> (i * 8)) & 0xff);  // big endian
    return t;
}

constexpr int poly_sz = 20;
const array<uint8_t, 8> png_file_signature = {{
    0x89, 'P', 'N', 'G',
    '\r', '\n', '\x1a', '\n',
}};
const array<uint8_t, 12> iend_chunk = {{
    0, 0, 0, 0,
    'I', 'E', 'N', 'D',
    0xae, 0x42, 0x60, 0x82,
}};

bool get_bit(uint32_t poly, uint32_t & r) {
    bool bit = r & (1 << (poly_sz - 1));
    bool new_bit = (__builtin_popcount(r & poly) & 1) ^ 1;
    constexpr uint32_t mask = (1 << poly_sz) - 1;
    r = ((r << 1) | new_bit) & mask;
    return bit;
}

uint8_t get_byte(array<uint32_t, 8> const & poly, array<uint32_t, 8> & r) {
    uint8_t acc = 0;
    REP (bit, 8) {
        acc |= get_bit(poly[bit], r[bit]) << bit;
    }
    return acc;
}

int main() {
    // input
    array<uint8_t, 25> ihdr_chunk;
    scanf("ihdr_chunk ");
    REP (i, 25) {
        int c; scanf("%d ", &c);
        ihdr_chunk[i] = c;
    }
    array<uint32_t, 8> iv;
    REP (bit, 8) {
        scanf("iv %u\n", &iv[bit]);
    }
    int size; scanf("encrypted_data %d\n", &size);
    vector<uint8_t> encrypted(size);
    REP (pos, size) {
        int c; scanf("%d ", &c);
        encrypted[pos] = c;
    }
    scanf("eof\n");

    // solve
    array<vector<uint32_t>, 8> candidates;
#pragma omp parallel for
    REP (poly, 1 << poly_sz) {
        array<uint32_t, 8> r = iv;
        array<bool, 8> is_mismatched = {};
        REP (pos, png_file_signature.size()) REP (bit, 8) {
            get_bit(poly, r[bit]);
        }
        REP (pos, ihdr_chunk.size()) REP (bit, 8) {
            bool expacted = (ihdr_chunk[pos] ^ encrypted[png_file_signature.size() + pos]) & (1 << bit);
            if (get_bit(poly, r[bit]) != expacted and ihdr_chunk[pos] != 0xff) {
                is_mismatched[bit] = true;
            }
        }
        if (not count(ALL(is_mismatched), false)) {
            continue;
        }
        REP (pos, size - png_file_signature.size() - ihdr_chunk.size() - iend_chunk.size()) REP (bit, 8) {
            get_bit(poly, r[bit]);
        }
        REP (pos, iend_chunk.size()) REP (bit, 8) {
            bool expacted = (iend_chunk[pos] ^ encrypted[size - iend_chunk.size() + pos]) & (1 << bit);
            if (get_bit(poly, r[bit]) != expacted) {
                is_mismatched[bit] = true;
            }
        }
        REP (bit, 8) {
            if (not is_mismatched[bit]) {
#pragma omp critical
                candidates[bit].push_back(poly);
            }
        }
    }

    // output
    make_crc_table();
    int64_t prod = 1;
    REP (bit, 8) {
        prod *= candidates[bit].size();
        cerr << "candidate " << bit << ": " << candidates[bit].size() << endl;
    }
#pragma omp parallel for
    for (int64_t index = 0; index < prod; ++ index) {
        array<uint32_t, 8> poly; {
            int64_t acc = index;
            REP_R (bit, 8) {
                poly[bit] = candidates[bit][acc % candidates[bit].size()];
                acc /= candidates[bit].size();
            }
        }
        array<uint32_t, 8> r = iv;
        string s;
        REP (pos, size) {
            s += (char)(encrypted[pos] ^ get_byte(poly, r));
            if (pos + 1 == png_file_signature.size() + ihdr_chunk.size()) {
                string t = s.substr(png_file_signature.size() + 4, ihdr_chunk.size() - 8);
                string u = s.substr(s.size() - 4);
                if (crc32(t) != u) {
                    s.clear();
                    break;
                }
            }
        }
        if (s.find("IDAT") == string::npos) {
            s.clear();
        }
        if (not s.empty()) {
#pragma omp critical
            cerr << "found " << index << ":";
            REP (bit, 8) cerr << " " << poly[bit];
            cerr << endl;
            string fname = ("flag." + to_string(index) + ".png");
            FILE *fp = fopen(fname.c_str(), "wb");
            REP (pos, size) {
                fprintf(fp, "%c", s[pos]);
            }
            fclose(fp);
        }
    }
    return 0;
}
```

<hr>

-   修正: 2018年  6月 27日 水曜日 10:54:52 JST
    -   PNGのmagicが `\x89PNG\r\n\r\n` になってた部分を修正。 実装に影響はない。 `\x89PNG\r\n\x1a\n` が正解
    -   よく気付いたなあと関心してしまった。発見者は eshiho です。感謝

<!-- {% endraw %} -->
