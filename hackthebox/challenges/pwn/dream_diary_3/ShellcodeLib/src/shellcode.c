#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include "_syscall.h"
#include "utils.h"

void* volatile realloc_hook = 0x4444444444444444;
void* volatile free_hook = 0x5555555555555555;
//Make sure to use static const arrays if you use any arrays, otherwise gcc might decide to add a
//call to memcpy
struct linux_dirent {
   unsigned long  d_ino;     /* Inode number */
   unsigned long  d_off;     /* Offset to next linux_dirent */
   unsigned short d_reclen;  /* Length of this linux_dirent */
   char           d_name[];  /* Filename (null-terminated) */
                     /* length is actually (d_reclen - 2 -
                        offsetof(struct linux_dirent, d_name)) */
};


void* _memset(void*s, int c, size_t n) {
    for (size_t i = 0; i < n; i++) {
        *(uint8_t*)((size_t)s + i) = 0;
    }
    return s;
}

size_t _strlen(char*s) {
    size_t ret = 0;
    while (s[ret] != '\0') {
        ret++;
    }
    return ret;
}
#define BUF_SIZE 1024
#define handle_error_static_msg(msg) \
        _write(1, msg, sizeof(msg)-1)


int _start(void)
{
    int fd, nread, fd2, nread_from_file;
    char buf[BUF_SIZE];
    char readbuf[256];
    struct linux_dirent *d;
    int bpos;
    size_t length;

    // try to clean up the mess in malloc
    //size_t n = (((size_t)free_hook) - ((size_t)realloc_hook));
    //_memset(realloc_hook, 0, n+8);
    // worst shell ever
    //_execveat(AT_FDCWD, "/bin/sh", NULL, NULL, 0);

    _memset(buf, 0, sizeof(buf));

    fd = _openat(AT_FDCWD, ".", O_RDONLY | O_DIRECTORY, 0000);
    if (fd <= -1) {
        handle_error_static_msg("open");
        goto exit;
    }

    for ( ; ; ) {
        nread = _getdents(fd, buf, BUF_SIZE);
        if (nread == -1) {
            handle_error_static_msg("getdents");
            goto exit;
        }

        if (nread == 0) {
            break;
        }

        for (bpos = 0; bpos < nread;) {
            d = (struct linux_dirent *) (buf + bpos);
            length = _strlen(d->d_name);
            _write(1, d->d_name, length);
            _write(1, "\n", 1);
            bpos += d->d_reclen;
            // Dump the first 256 bytes of the file
            fd2 = _openat(AT_FDCWD, d->d_name, O_RDONLY, 0000);
            if (fd2 <= -1) {
                continue;
            }
            nread_from_file = _read(fd2, readbuf, sizeof(readbuf));
            if (nread_from_file <= -1) {
                continue;
            }
            _write(1, readbuf, nread_from_file);
        }
    }

exit:
    return 0;
}
