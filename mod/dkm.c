/**
 * Rootkit detector kernel module
 **/

#define DEBUG

#define KBUILD_MODNAME "dkm"
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt // http://www.crashcourse.ca/wiki/index.php/Printk_and_variationss

#include <linux/elf.h> // elf headers
#include <linux/module.h> // struct module
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h> // __vmalloc
#include <linux/unistd.h> // NR_ sys calls constants

#include <net/sock.h>
#include <net/netlink.h>

#include "dkm.h"
#include "../comm.h" // communication config

// File operations snapshots. g_fpaths - files that should be verified
static const char *g_fpaths[] = { "/", "/proc" };
static const int g_nSnapshots = sizeof(g_fpaths) / sizeof(char*);
static struct fops_snapshot g_fops_snp[sizeof(g_fpaths) / sizeof(char*)];

// Syscall table entries snapshots. g_syscalls - syscalls # that should be verified
static const short g_syscalls[] = { __NR_read, __NR_write, __NR_open, __NR_creat, __NR_rename,
                                  __NR_unlink, __NR_link, __NR_chmod, __NR_init_module, __NR_delete_module, __NR_getdents };
static const int g_nSyscalls = sizeof(g_syscalls) / sizeof(short);
static struct syscallt_snapshot g_syscall_snp[sizeof(g_syscalls) / sizeof(short)];

// Netlink socket for KERNEL <--> USERSPACE comm
static struct sock *g_nl_sock;

static struct module *g_mod;        // where extracted module object will be stored
static struct dkm_hook hk_init_module;
LIST_HEAD(g_modlist);

static void **g_syscall_table;
asmlinkage long (*orig_init_module)(void __user*, unsigned long, const char*);
asmlinkage long (*orig_delete_module)(const char __user *, unsigned int);

/*
 * https://memset.wordpress.com/2011/01/20/syscall-hijacking-dynamically-obtain-syscall-table-address-kernel-2-6-x/
 */
void** find_syscall_table(void)
{
    void **sctable;
    unsigned int i = 0xC0000000;

    while (i < 0xD0000000) {
        sctable = (void **) i;

        if (sctable[__NR_close] == (void *) sys_close) {
            return sctable;
        }

        i += sizeof(void *);
    }
    return NULL;
}

asmlinkage long hooked_delete_module(const char __user *name_user, unsigned int flags)
{
    int ret;
    char name[DKM_MODNAME_SIZE];
    struct dkm_module *dkm_mod;

    // Call original delete_module
    ret = orig_delete_module(name_user, flags);

    // Module was successfully unloaded. Remove it from the list
    if(!ret) {
        if(strncpy_from_user(name, name_user, DKM_MODNAME_SIZE - 1) >= 0) {
            dkm_mod = find_mod(name);
            if(dkm_mod) {
                list_del(&dkm_mod->list);
                kfree(dkm_mod);
            }
        }
    }

    return ret;
}

asmlinkage long hooked_init_module(void __user *umod, unsigned long len, const char *uargs)
{
    Elf32_Ehdr *hdr = umod;
    Elf32_Shdr *sechdrs;
    char *secstrings;
    char name[MODULE_NAME_LEN];
    unsigned int modindex;

    int ret = 0;
    struct dkm_module *mod;

    // Extract module name from its image
    sechdrs = (void *)hdr + hdr->e_shoff;
    secstrings = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;
    modindex = find_sec(hdr, sechdrs, secstrings, ".gnu.linkonce.this_module");
    strncpy(name, (char*)(umod + sechdrs[modindex].sh_offset + 12), MODULE_NAME_LEN);

    // Prepare g_mod
    g_mod = NULL;

    // Call original init_module
    ret = orig_init_module(umod, len, uargs);

    if (!ret) {
        mod = kmalloc(sizeof(struct dkm_module), GFP_KERNEL);

        if (mod) {
            pr_info("Loaded module: THIS_MODULE - %X, name - %s\n", (unsigned int)g_mod, name);
            strncpy(mod->name, name, MODULE_NAME_LEN);
            mod->mod_ptr = g_mod;
            list_add(&mod->list, &g_modlist);
        }

        else {
            pr_err("Failed to allocate memory for new g_mod\n");
        }
    }

    pr_debug("init_module call intercepted - ret=%d\n", ret);
    return ret;
}

static void make_syscalls_snapshots(void)
{
    int i;

    if(!g_syscall_table) {
        return;
    }

    for(i = 0; i < g_nSyscalls; i++) {
        g_syscall_snp[i].call_id = g_syscalls[i];
        g_syscall_snp[i].addr = (unsigned long)g_syscall_table[g_syscalls[i]];
        memcpy(g_syscall_snp[i].op, (void*)g_syscall_snp[i].addr, SNAPSHOT_SIZE);
    }

    pr_info("Syscalls snapshots created\n");
}

static void verify_syscalls(void)
{
    int i, syscall_id;

    if(!g_syscall_table) {
        return;
    }

    for(i = 0; i < g_nSyscalls; i++) {

        syscall_id = g_syscall_snp[i].call_id;

        if( (unsigned long)g_syscall_table[syscall_id] != g_syscall_snp[i].addr ) {
            pr_info("Bad address for syscall_%d\n", syscall_id);

            preempt_disable();
            PROT_DISABLE;
                g_syscall_table[syscall_id] = (unsigned long*)g_syscall_snp[i].addr;
            PROT_ENABLE;
            preempt_enable();
        }

        if( memcmp(g_syscall_snp[i].op, g_syscall_table[syscall_id], SNAPSHOT_SIZE) ) {
            pr_info("Bad op codes for syscall_%d\n", syscall_id);
            memcpy_kernel_safe(g_syscall_table[syscall_id], g_syscall_snp[i].op, SNAPSHOT_SIZE);
        }
    }
}

static void make_fops_snapshots(void)
{
    struct file *f;
    void *func_addr;
    int i;

    for(i = 0; i < g_nSnapshots; i++) {

        if ((f = filp_open(g_fpaths[i], O_RDONLY, 0)) == NULL) {
            pr_err("%s cannot open file %s\n", __FUNCTION__, g_fpaths[i]);
            continue;
        }

        g_fops_snp[i].fpath = g_fpaths[i];

        func_addr = f->f_op->open;
        if(func_addr)
            memcpy(g_fops_snp[i].open, func_addr, SNAPSHOT_SIZE);

        func_addr = f->f_op->readdir;
        if(func_addr)
            memcpy(g_fops_snp[i].readdir, func_addr, SNAPSHOT_SIZE);

        func_addr = f->f_op->read;
        if(func_addr)
            memcpy(g_fops_snp[i].read, func_addr, SNAPSHOT_SIZE);

        func_addr = f->f_op->write;
        if(func_addr)
            memcpy(g_fops_snp[i].write, func_addr, SNAPSHOT_SIZE);

        filp_close(f, 0);

//        pr_info("readdir for %s ", g_fops_snp[i].fpath);
//        for(j=0; j < SNAPSHOT_SIZE; j++)
//            printk("%02X ", g_fops_snp[i].func_readdir[j]);
    }
     pr_info("FOPS snapshots created\n");
}

static int verify_fops(void)
{
    struct file *f;
    void *func_addr;
    int i;

    for(i = 0; i < g_nSnapshots; i++) {

        if ((f = filp_open(g_fops_snp[i].fpath, O_RDONLY, 0)) == NULL) {
            pr_err("%s cannot open file %s\n", __FUNCTION__, g_fpaths[i]);
            continue;
        }

        func_addr = f->f_op->open;
        if( func_addr && memcmp(g_fops_snp[i].open, func_addr, SNAPSHOT_SIZE) ) {
            pr_info("Bad OPEN for %s\n", g_fops_snp[i].fpath);
            memcpy_kernel_safe(func_addr, g_fops_snp[i].open, SNAPSHOT_SIZE);
        }

        func_addr = f->f_op->readdir;
        if( func_addr && memcmp(g_fops_snp[i].readdir, func_addr, SNAPSHOT_SIZE) ) {
            pr_info("Bad READDIR for %s\n", g_fops_snp[i].fpath);
            memcpy_kernel_safe(func_addr, g_fops_snp[i].readdir, SNAPSHOT_SIZE);
        }

        func_addr = f->f_op->read;
        if( func_addr && memcmp(g_fops_snp[i].read, func_addr, SNAPSHOT_SIZE) ) {
            pr_info("Bad READ for %s\n", g_fops_snp[i].fpath);
            memcpy_kernel_safe(func_addr, g_fops_snp[i].read, SNAPSHOT_SIZE);
        }

        func_addr = f->f_op->write;
        if( func_addr && memcmp(g_fops_snp[i].write, func_addr, SNAPSHOT_SIZE) ) {
            pr_info("Bad WRITE for %s\n", g_fops_snp[i].fpath);
            memcpy_kernel_safe(func_addr, g_fops_snp[i].write, SNAPSHOT_SIZE);
        }

        filp_close(f, 0);
    }

    return 0;
}

static struct dkm_module* find_mod(char* mod_name)
{
    struct dkm_module *dkm_mod;

    if(!mod_name) {
        return NULL;
    }

    list_for_each_entry(dkm_mod, &g_modlist, list) {
        if( !strncmp(dkm_mod->name, mod_name, DKM_MODNAME_SIZE) ) {
            return dkm_mod;
        }
    }
    return NULL;
}

static int mod_unhide(char *mod_name)
{
    struct module *entry;
    struct dkm_module* dkm_mod = find_mod(mod_name);

    if(!dkm_mod || !dkm_mod->mod_ptr) {
        return -1;
    }

//    pr_devel("%s %s\n", __FUNCTION__, mod_name);
    // Traverse forward
    list_for_each_entry(entry, &THIS_MODULE->list, list) {
        if( !strncmp(dkm_mod->name, entry->name, DKM_MODNAME_SIZE) ) {
            pr_info("%s already in list\n", entry->name);
            return -1;
        }
    }

    preempt_disable();
    list_add_tail(&dkm_mod->mod_ptr->list, &THIS_MODULE->list); // add module to KMList
    preempt_enable();

    return 0;
}

static int mod_unprotect(char *mod_name)
{
    struct dkm_module* dkm_mod = find_mod(mod_name);

    if(!dkm_mod || !dkm_mod->mod_ptr) {
        return -1;
    }
//    pr_devel("%s %s\n", __FUNCTION__, mod_name);

    // Don't reduce ref counter if it is already 0
    if(module_refcount(dkm_mod->mod_ptr) > 0) {
        module_put(dkm_mod->mod_ptr);
    }

    return 0;
}

//static int send_reply(struct nlmsghdr *nlh, int seq_number, int pid)
//{
//    int ret = 0;

//    skb_out = nlmsg_new(sizeof(struct dkm_command), 0);
//    if (!skb_out) {
//        pr_err("Failed to allocate socket buffer\n");
//        return -DKM_ERR_SOCKET_NOMEM;
//    }
//    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
//}

static int send_mod_list(struct nlmsghdr *nlh, int seq_number, int pid)
{
    int ret = 0, space_left = DKM_MSG_SIZE;
    struct dkm_modinfo modinfo;
    struct dkm_module *dkm_mod;
    struct sk_buff *skb_out;

    skb_out = nlmsg_new(space_left, 0);
    if (!skb_out) {
        pr_err("Failed to allocate socket buffer\n");
        return -DKM_ERR_SOCKET_NOMEM;
    }
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

    list_for_each_entry(dkm_mod, &g_modlist, list) {

        if(space_left < sizeof(struct dkm_modinfo)) {
            // Socket buffer is out of space, too many modules
            // TODO: implement chain messages for this case
            break;
        }

        // Fill message structure
        modinfo.mod_addr = (unsigned int)dkm_mod->mod_ptr;
        strncpy(modinfo.name, dkm_mod->name, MODULE_NAME_LEN);

        // Put structure in the socket buffer
        nlh = nlmsg_put(skb_out, 0, ++seq_number, DKM_MSG_TYPE, sizeof(struct dkm_modinfo), NLM_F_MULTI);
        memcpy(nlmsg_data(nlh), &modinfo, sizeof(struct dkm_modinfo));
        space_left -= sizeof(struct dkm_modinfo);
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, 0, 0);
    ret = nlmsg_unicast(g_nl_sock, skb_out, pid);
    return ret;
}

DEFINE_MUTEX(comm_mutex);
static int dkm_proccess_command(struct sk_buff *skb, struct nlmsghdr *nlh)
{
    int seq, type, pid;
    struct dkm_command *cmd;

    pid = nlh->nlmsg_pid;
    type = nlh->nlmsg_type;
    seq = nlh->nlmsg_seq;

    if (type != DKM_MSG_TYPE) {
        pr_info("Wrong message type %X\n", type);
        return -EINVAL;
    }

    cmd = NLMSG_DATA(nlh);

    if( !cmd || nlh->nlmsg_len < sizeof(struct dkm_command) ) {
        pr_info("Not a command received\n");
        return -EINVAL;
    }

    if (cmd->key != DKM_AUTH_KEY) {
        pr_info("Wrong auth key\n");
        return -EINVAL;
    }

    pr_info("Received command %d\n", cmd->cmd_id);

    switch(cmd->cmd_id) {
    case DKM_CMD_GET_LIST:
        send_mod_list(nlh, seq, pid);
        break;
    case DKM_CMD_UNHIDE:
        mod_unhide( (char*)(NLMSG_DATA(nlh) + sizeof(struct dkm_command) ) );
        break;
    case DKM_CMD_UNPROTECT:
        mod_unprotect( (char*)(NLMSG_DATA(nlh) + sizeof(struct dkm_command) ) );
        break;
    case DKM_CMD_VERIFY_FOPS:
        verify_fops();
        break;
    case DKM_CMD_VERIFY_SYSCALLS:
        verify_syscalls();
        break;
    default:
        break;
    }

    return 0;
}


static void dkm_rcv_msg(struct sk_buff *skb)
{
    mutex_lock(&comm_mutex);
    netlink_rcv_skb(skb, dkm_proccess_command);
    mutex_unlock(&comm_mutex);
}

static int set_comm(void)
{
    g_nl_sock = netlink_kernel_create(&init_net, DKM_PROTOCOL, 0, dkm_rcv_msg, NULL, THIS_MODULE);
    if (!g_nl_sock) {
         pr_err("Failed to create netlink socket\n");
         return -ENOMEM;
    }

    return 0;
}

static int hook_apply(struct dkm_hook *hk)
{
    // Allocate executable page for the stub
    char *hookStub = __vmalloc(20, GFP_KERNEL, PAGE_KERNEL_EXEC);

    if (!hookStub) {
        pr_err("Failed to allocate executable page for the stub\n");
        return -ENOMEM;
    }

    pr_devel("stub=%X g_mod=%p\n", (unsigned int)hookStub, (void*)&g_mod);

    // Calc hook address
    hk->hookAddr = (unsigned char*)(hk->baseAddr + hk->offset);
    hk->stub = hookStub;

    memcpy(hk->originalBytes, hk->hookAddr, HOOK_LEN); // save original bytes
    preempt_disable();
    PROT_DISABLE;
    /* Patch original function  */
        hk->hookAddr[0] = 0x68; // PUSH
        *(unsigned long *)&(hk->hookAddr)[1] = (unsigned long)hookStub; // stub's address
        hk->hookAddr[5] = 0xC3; // RETN
        // Trampoline is 6 bytes, so
        memset(&hk->hookAddr[6], '\x90', HOOK_LEN - 6); // Fill left spaces with NOP(s)

    /* Build stub       */
        hookStub[0] = 0xA3; // MOV FROM EAX
        *(unsigned long *)&hookStub[1] = (unsigned long)&g_mod; // to dword ptr [g_mod]
        memcpy(&hookStub[5], hk->originalBytes, HOOK_LEN); // execute original opcodes
        hookStub[12] = 0x68; // PUSH
        *(unsigned long *)&hookStub[13] = (unsigned long)(hk->hookAddr + HOOK_LEN); // address to original function
        hookStub[17] = 0xC3; // RETN ** Trampoline
    PROT_ENABLE;
    preempt_enable();

    pr_info("init_module() patched\n");

    return 0;
}

static void hook_remove(struct dkm_hook *hk)
{
    preempt_disable();
    PROT_DISABLE;
        memcpy(hk->hookAddr, hk->originalBytes, HOOK_LEN);
    PROT_ENABLE;
    preempt_disable();

    if (hk->stub) {
        vfree((void*)hk->stub);
    }
}

static int __init mod_init(void)
{
    pr_info("Loaded\n");

    // Create communication channel
    if (set_comm() < 0) {
        goto init_err;
    }

    g_syscall_table = find_syscall_table();
    pr_devel("sys_call_table at %p\n", g_syscall_table);

    hk_init_module.baseAddr = (unsigned long)g_syscall_table[__NR_init_module];
    hk_init_module.offset = find_pattern((void*)hk_init_module.baseAddr, HOOK_PATTERN, HOOK_LEN, HOOK_MEM_SCAN_SIZE);

    // Replace syscall_table entries
    preempt_disable();
    PROT_DISABLE;
        orig_init_module = xchg(&g_syscall_table[__NR_init_module], hooked_init_module);
        orig_delete_module = xchg(&g_syscall_table[__NR_delete_module], hooked_delete_module);
    PROT_ENABLE;
    preempt_enable();

    // Hooks
    if(!hk_init_module.offset || hook_apply(&hk_init_module) < 0) {
        pr_err("Cannot create INLINE hook in init_module(). Module address extraction disabled\n");
    }

    make_fops_snapshots();
    make_syscalls_snapshots();

    return 0;

init_err:

    return -1;
}

static void __exit mod_exit(void)
{
    struct dkm_module *mod, *tmp;

    // Remove systable hooks
    preempt_disable();
    PROT_DISABLE;
        g_syscall_table[__NR_init_module] = orig_init_module;
        g_syscall_table[__NR_delete_module] = orig_delete_module;
    PROT_ENABLE;
    preempt_enable();

    // If stub was not allocated, then hook was not applied
    if(hk_init_module.stub) {
        hook_remove(&hk_init_module);
    }

    // Free dkm_modules list
    list_for_each_entry_safe(mod, tmp, &g_modlist, list) {
        list_del(&mod->list);
        kfree(mod);
    }

    if (g_nl_sock) {
        netlink_kernel_release(g_nl_sock);
    }
}

module_init(mod_init);
module_exit(mod_exit);
