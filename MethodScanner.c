/*
 *
 * Author: Grant Douglas (@Hexploitable)
 *
 * Description: Use this when the binary has been stripped and the function isn't exported.
 *              I.e. when you can't use MSFindSymbol().
 *
 * Usage:       Open app in disassembler, grab first 16 bytes (might need to tweak this)
 *              of your target method. Use this as signature.
 *
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/vm_map.h>
#include <mach-o/dyld_images.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#define red   "\033[1;31m"        /* 0 -> normal ;  31 -> red */
#define redU   "\033[4;31m"
#define cyan  "\033[0;36m"        /* 1 -> bold ;  36 -> cyan */
#define cyanU "\033[4;36m"
#define green "\033[0;32m"        /* 4 -> underline ;  32 -> green */
#define yellow "\033[0;33m"
#define yellowU "\033[4;33m"
#define blue  "\033[0;34m"        /* 9 -> strike ;  34 -> blue */
#define blueU "\033[4;34m"
#define black  "\033[0;30m"
#define brown  "\033[0;33m"
#define magenta  "\033[0;35m"
#define gray  "\033[0;37m"
#define uline   "\033[4;0m"
#define none   "\033[0m"        /* to flush the previous property */

int pid = 0;
int g_pid = 0;
int needleLen = 0;
unsigned char *nBuffer;

mach_vm_address_t *scanMem(int pid, mach_vm_address_t addr, mach_msg_type_number_t size)
{
    task_t t;
    task_for_pid(mach_task_self(), pid, &t);
    mach_msg_type_number_t dataCnt = size;
    mach_vm_address_t max = addr + size;
    int bytesRead = 0;
    kern_return_t kr_val;
    pointer_t memStart;
    uint32_t sz;
    unsigned char buffer[needleLen];

    while (bytesRead < size)
    {
        if ((kr_val = vm_read(t, addr, needleLen, &memStart, &sz)) == KERN_SUCCESS)
        {
            memcpy(buffer, (const void *)memStart, sz);
            if (memcmp(buffer, nBuffer, needleLen) == 0)
            {
                fflush(stdout);
                return (unsigned long long *)addr;
            }
            else
                printf("[%s-%s] %s%p%s ---> vm_read()\r", red, none, redU, addr, none);
            fflush(stdout);
        }
        else
        {
            printf("[%s-%s] %s%p%s ---> vm_read()\r", red, none, redU, addr, none);
            fflush(stdout);
        }
        addr += sizeof(unsigned char);
        bytesRead += sizeof(unsigned char);
    }
    printf("[%si%s] Scanning ended without a match.\r\n", yellow, none);
    fflush(stdout);
    return NULL;
}

unsigned int *getMemRegions(task_t task, vm_address_t address)
{
    kern_return_t kret;
    vm_region_basic_info_data_t info;
    vm_size_t size;
    mach_port_t object_name;
    mach_msg_type_number_t count;
    vm_address_t firstRegionBegin;
    vm_address_t lastRegionEnd;
    vm_size_t fullSize;
    count = VM_REGION_BASIC_INFO_COUNT_64;
    int regionCount = 0;
    int flag = 0;

    while (flag == 0)
    {
        //Attempts to get the region info for given task
        kret = mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t) &info, &count, &object_name);
        if (kret == KERN_SUCCESS)
        {
            if (regionCount == 0)
            {
                firstRegionBegin = address;
                regionCount += 1;
            }
            fullSize += size;
            address += size;
        }
        else
            flag = 1;
    }
    lastRegionEnd = address;
    printf("[%si%s] Proc Space: %s%p%s - %s%p%s\n", yellow, none, yellowU, firstRegionBegin, none, blueU, lastRegionEnd, none);
    unsigned int *ptrToFunc = (unsigned int *)scanMem(pid, firstRegionBegin, fullSize);
    return ptrToFunc;
}


int main(int argc, char** argv) {
    kern_return_t rc;
    mach_port_t task;
    mach_vm_address_t addr = 1;

    if (argc >= 3)
    {
        pid = atoi(argv[1]);
        g_pid = pid; //Required for fw >= 6.0    
        rc = task_for_pid(mach_task_self(), pid, &task);
        if (rc)
        {
            fprintf(stderr, "[%s-%s] task_for_pid() failed, error %d - %s%s", red, none, rc, red, mach_error_string(rc), none);
            exit(1);
        }

        FILE *f = fopen(argv[2], "rb");
        if (f)
        {
            fseek(f, 0, SEEK_END);
            needleLen = ftell(f);
            fclose(f);
        }
        
        unsigned char buf[needleLen+1];
        FILE *fr;
        fr = fopen(argv[2], "rb");
        long int cnt = 0;
        while ((cnt = (long)fread(buf, sizeof(unsigned char), 16, fr))>0)
            nBuffer = buf;
        fclose(fr);

        printf("[%s+%s] PID: %s%d%s\n", green, none, blueU, pid, none);
        printf("[%si%s] Task: %s%d%s\n", yellow, none, blueU, task, none);
        printf("[%s+%s] Needle Length: %s%d%s %sbytes%s\n", green, none, blue, needleLen, none, blueU, none);
        unsigned int *sym = getMemRegions(task, addr);
        if (sym != NULL)
            printf("\n\n[%s$%s] Located target function ---> %s%p%s\n\n", cyan, none, cyanU, sym, none);
        else
            printf("[%s-%s] Didn\'t find the function.\n", red, none);
    }
    else
        fprintf(stderr, "[%s-%s] Usage: %s <pid> <Path to file containing needle>\n", red, none, argv[0]);
    return 0;
}
