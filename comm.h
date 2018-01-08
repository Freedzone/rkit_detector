/*  This is the configuration file that describes
 *  communication protocol between kernel module user space program.
 *  This file is common for kernel module and control application.
 */

/* CP from source */
/* Chosen so that structs with an unsigned long line up. */
#define DKM_MODNAME_SIZE (64 - sizeof(unsigned long))
#define DKM_MSG_SIZE 2048

#define DKM_AUTH_KEY 55555
#define DKM_MSG_TYPE (0x10 + 2)  // + 2 is arbitrary. same value for kern/usr
#define DKM_PROTOCOL 31

enum ERRORS {
    DKM_ERR,
    DKM_ERR_MOD_NOT_FOUND,
    DKM_ERR_SOCKET_NOMEM,
};

enum CMDS {
    DKM_CMD_GET_LIST,
    DKM_CMD_UNHIDE,
    DKM_CMD_UNPROTECT,
    DKM_CMD_VERIFY_FOPS,
    DKM_CMD_VERIFY_SYSCALLS
};

struct dkm_command {
    unsigned int key;
    unsigned int cmd_id;
    int dkm_error; // detector error code, if exists
    int sys_error; // system error code, if exists
};


/* This structure is used to send\retrieve modules info */
struct dkm_modinfo {
    char name[DKM_MODNAME_SIZE];
    unsigned int mod_addr;
};
