#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/kernel.h>

#include <netlink/netlink.h>

#include "../comm.h"

const char *menu_txt =
        "1. Get loaded modules list\n"
        "2. Print loaded modules list\n"
        "3. Unhide module\n"
        "4. Unprotect module\n"
        "5. Verify fops\n"
        "6. Verify syscalls\n"
        "0. Exit\n";

char stdin_buf[2000], *end_ptr;
int mod_quant;
struct dkm_modinfo *modules_info;

/**
 * Callback function for unhide\unprotect command
 **/
void cb_module_set(struct nlmsghdr *hdr, int msg_size)
{
    struct dkm_command *comm_res;

    comm_res = NLMSG_DATA(hdr);
}

/**
 * Callback function get module list command
 **/
void cb_modules_get(struct nlmsghdr *hdr, int msg_size)
{
    struct dkm_modinfo *modinfo;

    // Clear old data
    if(modules_info) {
        free(modules_info);
        modules_info = NULL;
        mod_quant = 0;
    }

    modules_info = (struct dkm_modinfo *) malloc(msg_size);
    for (; NLMSG_OK (hdr, msg_size);
            hdr = NLMSG_NEXT (hdr, msg_size)) {

        // Multipart message ended
        if (hdr->nlmsg_type == NLMSG_DONE) {
            break;
        }

        modinfo = NLMSG_DATA(hdr);
        memccpy(&modules_info[mod_quant], modinfo, 1, hdr->nlmsg_len);
        mod_quant++;
//        printf("Received: %s msg_type=%d msg_len=%d msg_flags=%d\n", modinfo->name, hdr->nlmsg_type, hdr->nlmsg_len, hdr->nlmsg_flags);
    }
}

void modules_print()
{
    int i;
    if(mod_quant <= 0) {
        printf("\tNo modules\n");
        return;
    }

    printf("\n");
    for(i = 0; i < mod_quant; i++) {
        printf("\t%d. %-20s 0x%08X\n", i+1, modules_info[i].name, modules_info[i].mod_addr);
    }
}

char *input_mod_name()
{
    int id;
    if(mod_quant <= 0) {
        printf("\tNo modules\n");
        return NULL;
    }

    modules_print();

    printf("\tInput module #(0 to exit): "); fgets(stdin_buf, sizeof(stdin_buf), stdin);

    errno = 0;
    id = strtol(stdin_buf, &end_ptr, 10);

    // cannot convert input to integer
    if(errno || stdin_buf == end_ptr) {
        printf("\tWrong input\n");
        return NULL;
    }

    id--;

    if(id >= 0 && id < mod_quant) {
        return modules_info[id].name;
    }
    return NULL;
}

/**
 * send_command - send command to kernel module and process reply
 * @nlh: netlink handle
 * @dkm_comm: command instance
 * @data: data to send, besides command
 * @data_size: size of the additional data
 * @recv_func: callback function
 **/
int send_netlink(struct nl_handle *nlh, struct dkm_command *dkm_comm,
                 void *data, size_t data_size,
                 void (*recv_func)(struct nlmsghdr * hdr, int msg_size) )
{
    struct nlmsghdr *hdr;
    struct sockaddr_nl nla;
    char *pBuf;
    void *sendBuf = dkm_comm; // if no additional data, send only the command instance
    int ret, payload_size = sizeof(struct dkm_command) + data_size;

    if(data) {
        if(payload_size > DKM_MSG_SIZE) {
            printf("Payload exceeds the maximum size.\n");
            return -1;
        }
        // Create new buffer with both command and data
        sendBuf = malloc(payload_size);
        memcpy(sendBuf, dkm_comm, sizeof(struct dkm_command));
        memcpy(sendBuf + sizeof(struct dkm_command), data, data_size);
        printf("Appended data=\"%s\" size=%d\n", (char*)data, payload_size);
    }


    ret = nl_send_simple(nlh, DKM_MSG_TYPE, 0, sendBuf, payload_size);

    // If does not equal, that it was allocated
    if(sendBuf != dkm_comm) {
        free(sendBuf);
    }

    if (ret < 0) {
        nl_perror(ret, "nl_send_simple fail");
        return ret;
    }

    printf("Command %d sent\n\n", dkm_comm->cmd_id);


    ret = nl_recv(nlh, &nla, (unsigned char**)&pBuf, NULL);
    if (ret < 0) {
        nl_perror(ret, "nl_recv");
        return ret;
    }

    hdr = (struct nlmsghdr*)pBuf;

    // Error or early ACK received
    if(hdr->nlmsg_type == NLMSG_ERROR) {
        printf("No reply received\n");
        return ret;
    }

    if(recv_func) {
        recv_func(hdr, ret);
    }

    // RCV ACK message
    nl_wait_for_ack(nlh);

    return ret;
}

int main(int argc, char **argv)
{
    struct dkm_command dkm_comm;
    struct nl_handle *nlh;
    char *mod_name;
    int key_input;
    int ret;

    nlh = nl_handle_alloc();
    if (!nlh) {
        printf("bad nl_socket_alloc\n");
        return EXIT_FAILURE;
    }

    ret = nl_connect(nlh, DKM_PROTOCOL);
    if (ret < 0) {
        nl_perror(ret, "nl_connect");
        nl_handle_destroy(nlh);
        return EXIT_FAILURE;
    }

    dkm_comm.key = DKM_AUTH_KEY;
    do {

        printf("\n\n%s", menu_txt);
        printf("Enter option: "); fgets(stdin_buf, sizeof(stdin_buf), stdin);

        errno = 0;
        key_input = strtol(stdin_buf, &end_ptr, 10);

        // cannot convert input to integer
        if(errno || stdin_buf == end_ptr) {
            key_input = -1;
            printf("Wrong input\n");
            continue;
        }

        switch(key_input) {
        case 1:
            dkm_comm.cmd_id = DKM_CMD_GET_LIST;
            send_netlink(nlh, &dkm_comm, NULL, 0, cb_modules_get);
            break;
        case 2:
            modules_print();
            break;
        case 3:
            mod_name = input_mod_name();
            dkm_comm.cmd_id = DKM_CMD_UNHIDE;
            if(mod_name)
                send_netlink(nlh, &dkm_comm, mod_name, DKM_MODNAME_SIZE, NULL);
            break;
        case 4:
            mod_name = input_mod_name();
            dkm_comm.cmd_id = DKM_CMD_UNPROTECT;
            if(mod_name)
                send_netlink(nlh, &dkm_comm, mod_name, DKM_MODNAME_SIZE, NULL);
            break;
        case 5:
            dkm_comm.cmd_id = DKM_CMD_VERIFY_FOPS;
            send_netlink(nlh, &dkm_comm, NULL, 0, NULL);
            break;
        case 6:
            dkm_comm.cmd_id = DKM_CMD_VERIFY_SYSCALLS;
            send_netlink(nlh, &dkm_comm, NULL, 0, NULL);
            break;
        default:
            break;
        }
    }
    while(key_input != 0);

    nl_close(nlh);
    nl_handle_destroy(nlh);

    return EXIT_SUCCESS;
}

