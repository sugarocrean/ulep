#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h> 


#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

static void
access_invalid_va_kmod(int argc, char *argv[])
{
    char *m = malloc(0x100000); 
    if (!m)
        handle_error("malloc");
    free(m);

    int fd = open("/proc/cmdline", O_RDONLY);
    if (fd == -1)
        handle_error("open");
    read(fd, m, 0x100000);
}

static void
access_non_mapped_va_kmod(int argc, char *argv[])
{
    char *m = malloc(0x100000); 
    if (!m)
        handle_error("malloc");

    int fd = open("/proc/cmdline", O_RDONLY);
    if (fd == -1)
        handle_error("open");
    read(fd, m, 0x100000);
}

static void
write_ro_data_umod(int argc, char *argv[])
{
    char *s = "abc";
    *s = 0x00;
}

static void
anno_mmp(int argc, char *argv[])
{
    int ret;
    size_t mlen = 0x100000;
    size_t half_mlen = mlen / 2; 
    char *m = mmap(NULL, mlen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
        handle_error("malloc");

    printf("mmap(): val=0x%lx\n", (unsigned long)m);

    memset(m, 0, mlen); 

    ret = munmap(m, half_mlen);      
    if (ret)
        handle_error("munmap");

    m[half_mlen] = 0;
    m[mlen - 1]  = 0;
}

static void
interrupt(int signal)  
{ 
    printf("interrupt occur: %d\n", signal); 
} 

static void
signal_test(int argc, char *argv[])
{
    if (signal(SIGINT, interrupt) == SIG_ERR)
        handle_error("signal");

    if (raise(SIGINT) != 0)
        handle_error("raise");
}

static void
hpage_test(int argc, char *argv[])
{
    int fd = open("/dev/hugepages/test", O_CREAT | O_RDWR, 0600); 
    if (fd < 0)
        handle_error("open");

    size_t hugepage_sz = 2 * (1ul << 21); /* 2 huge pages */
    char *vma = mmap(NULL, hugepage_sz, PROT_READ | PROT_WRITE, 
                     MAP_SHARED, fd, 0);
                     //MAP_SHARED | MAP_POPULATE, fd, 0);
    if (vma == MAP_FAILED) {
        close(fd);
        handle_error("mmap()");
    }

    memset(vma, 0, hugepage_sz);
}

static void
malloc_bigmem_test(int argc, char *argv[])
{
    size_t msize;

    msize = 1ul << 30; 
    if (argc > 0)
        msize = 1ul << atoi(argv[0]);

    printf("mmap size 0x%lx\n", msize);
    char *m = mmap(NULL, msize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
        handle_error("malloc()");

    printf("mmap(): %p, start to memset()\n", m);
    memset(m, 0, msize);
    printf("memset() is done\n");
    pause();
}

typedef void (*crun_func_t)(int argc, char *argv[]);

struct {
    int id;
    const char *help;
    crun_func_t func;
} vm_hack_cases[] = {
    { .id = 0, 
      .help = "access the non-existent vma in kernel space",
      .func = access_invalid_va_kmod,
    },
    { .id = 1, 
      .help = "access the vma which has not pages mapped in kernel space",
      .func = access_non_mapped_va_kmod,
    },
    { .id = 2, 
      .help = "write ro data",
      .func = write_ro_data_umod,
    },
    { .id = 3, 
      .help = "anon mapping(page->index)",
      .func = anno_mmp,
    },
    { .id = 4, 
      .help = "huge page test",
      .func = hpage_test,
    },
    { .id = 5, 
      .help = "signal test",
      .func = signal_test,
    },
    { .id = 6, 
      .help = "big malloc test",
      .func = malloc_bigmem_test,
    },
};

static void
usage(void)
{
    int i;

    printf("usage: ./vmtest [case id]\n");
    for (i = 0; i < ARRAY_SIZE(vm_hack_cases); i++) {
        printf("%d: %s\n", vm_hack_cases[i].id, vm_hack_cases[i].help);
    }
}

int
main(int argc, char *argv[])
{
    int i;
    int cid;

    if (argc < 2) {
        usage();
        exit(-1);
    }  

    cid = atoi(argv[1]);

    argc -= 2;
    argv += 2;

    for (i = 0; i < ARRAY_SIZE(vm_hack_cases); i++)
        if (vm_hack_cases[i].id == cid) {
            vm_hack_cases[i].func(argc, argv);
            break;
        }

    if (i >= ARRAY_SIZE(vm_hack_cases))
        printf("invalid case id\n");

    exit(EXIT_SUCCESS);
}
