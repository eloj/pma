# Overview

This repo contains some code for my Memory allocation/pointer elimination experiments.

I would not advice using this code for anything serious.

## Example run

```bash
$ make && ./pma_test 4

arg1 alignment=4 (16 bytes)
HW page size=4096
Allocated new 4096 byte page @ 0x21cb020
First page at 0x21cb020
Page header is 16 bytes, 4080 bytes available (4 bytes slack). Max allocation size is 4080 bytes.
0 @[000000] = 'Hello'
1 @[000001] = 'World'
2 @[000002] = '!'
Aligned to 4, '<a string at the end of the page>' takes 48 bytes (14 bytes slack).
Allocated new 4096 byte page @ 0x21cc030
>>>@[000252] = '<a string at the end of the page>' == '<a string at the end of the page>'
Writing page @ 0x21cb020 to test-p0000.bin (4096 bytes)
Writing page @ 0x21cc030 to test-p0001.bin (4096 bytes)
Freeing 4096 page (4096 used/0 free) @ 0x21cb020 (.next=0x21cc030)
Freeing 4096 page (4096 used/0 free) @ 0x21cc030 (.next=(nil))

$ hexdump -C test-p0000.bin
00000000  c0 86 97 00 00 00 00 00  00 10 00 00 00 00 00 00  |................|
00000010  48 65 6c 6c 6f 00 00 00  00 00 00 00 00 00 00 00  |Hello...........|
00000020  57 6f 72 6c 64 00 00 00  00 00 00 00 00 00 00 00  |World...........|
00000030  21 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |!...............|
00000040  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|
*
00001000

$ hexdump -C test-p0001.bin
00000000  00 00 00 00 00 00 00 00  00 10 00 00 00 00 00 00  |................|
00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000fd0  3c 61 20 73 74 72 69 6e  67 20 61 74 20 74 68 65  |<a string at the|
00000fe0  20 65 6e 64 20 6f 66 20  74 68 65 20 70 61 67 65  | end of the page|
00000ff0  3e 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |>...............|
00001000
```

