#ifndef _DKM_H
#define _DKM_H

MODULE_LICENSE("GPL");                      //< The license type -- this affects runtime behavior
MODULE_AUTHOR("Maksym Hryhorenko");         //< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Kernel mod detector for test rootkit");  //< The description -- see modinfo
MODULE_VERSION("1");                      //< The version of the module

/* http://dandylife.net/blog/archives/304
** CPU protection mode control. CR0 bit 16 - write protect */
#define PROT_ENABLE write_cr0(read_cr0() | 0x10000)      // CR0 protection Enabled
#define PROT_DISABLE write_cr0(read_cr0() & (~ 0x10000)) // CR0 protection Disabled


#define SNAPSHOT_SIZE 20 // how many bytes of function to snapshot

#define HOOK_PATTERN "\x3D\x00\xF0\xFF\xFF\x89\xC6" // pattern to ensure that hook will be applied at the right place
#define HOOK_MEM_SCAN_SIZE 200 // pattern scanning space
#define HOOK_LEN 7

struct fops_snapshot {
    unsigned char open[SNAPSHOT_SIZE];
    unsigned char readdir[SNAPSHOT_SIZE];
    unsigned char read[SNAPSHOT_SIZE];
    unsigned char write[SNAPSHOT_SIZE];
    const char *fpath;
};

struct syscallt_snapshot {
    char op[SNAPSHOT_SIZE]; // op codes
    unsigned int call_id;
    unsigned long addr;
};

struct dkm_module {
    char name[MODULE_NAME_LEN];
    struct module *mod_ptr;
    struct list_head list;
};

struct dkm_hook {
    char originalBytes[HOOK_LEN];
    unsigned long baseAddr;
    unsigned long offset;
    char *hookAddr; // baseAddr + offset
    char *stub;
};

static struct dkm_module* find_mod(char *mod_name);

static unsigned int find_sec(Elf32_Ehdr *hdr, Elf32_Shdr *sechdrs, const char *secstrings, const char *name);
static void* memcpy_kernel_safe(void *dest, const void *src, __kernel_size_t bytes);
static unsigned long find_pattern(void *baseAddr, char *pattern, __kernel_size_t len, __kernel_size_t search_len);

/* Find a module section: 0 means not found.
   Not exported. CPed from http://lxr.free-electrons.com/source/kernel/module.c?v=2.6.32#L135
*/
static unsigned int find_sec(Elf32_Ehdr *hdr, Elf32_Shdr *sechdrs, const char *secstrings, const char *name)
{
    unsigned int i;

    for (i = 1; i < hdr->e_shnum; i++)
            /* Alloc bit cleared means "ignore it." */
            if ((sechdrs[i].sh_flags & SHF_ALLOC)
                && strcmp(secstrings+sechdrs[i].sh_name, name) == 0)
                    return i;
    return 0;
}

/* Use this to memcpy into write_protected memory region */
static void* memcpy_kernel_safe(void *dest, const void *src, __kernel_size_t bytes)
{
    void* ret;
    if(!dest || !src)
        return NULL;

    preempt_disable();
    PROT_DISABLE;
    ret = memcpy(dest, src, bytes);
    PROT_ENABLE;
    preempt_enable();

    return ret;
}

/* Locate pattern inside kernel memory region
   returns offset of found pattern or 0; */
static unsigned long find_pattern(void *baseAddr, char *pattern, __kernel_size_t len, __kernel_size_t search_len)
{
    int off;

    if(!baseAddr || !pattern) {
        return 0;
    }

    for(off = 0; off < search_len; off++) {
        if( !memcmp(baseAddr + off, pattern, len) )
            return off;
    }

    return 0;
}

#endif
