#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <ps5/kernel.h>
#include <ps5/mdbg.h>
#include "util.h"

typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;


int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);


int notify(char* msg) {
  notify_request_t req;

  bzero(&req, sizeof req);
  strncpy(req.message, msg, sizeof req.message);

  return sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
}


int toast(char* title, char* body){
    static const char* toast_tmpl =
                                      "{\n"
                                      "  \"rawData\": {\n"
                                      "    \"viewTemplateType\": \"InteractiveToastTemplateB\",\n"
                                      "    \"channelType\": \"Downloads\",\n"
                                      "    \"useCaseId\": \"IDC\",\n"
                                      "    \"toastOverwriteType\": \"No\",\n"
                                      "    \"isImmediate\": true,\n"
                                      "    \"priority\": 100,\n"
                                      "    \"viewData\": {\n"
                                      "      \"icon\": {\n"
                                      "        \"type\": \"Url\",\n"
                                      "        \"parameters\": {\n"
                                      "          \"url\": \"/system_tmp/icon.svg\"\n"
                                      "        }\n"
                                      "      },\n"
                                      "      \"message\": {\n"
                                      "        \"body\": \"%s\"\n"
                                      "      },\n"
                                      "      \"subMessage\": {\n"
                                      "        \"body\": \"%s\"\n"
                                      "      },\n"
                                      "      \"actions\": [\n"
                                      "        {\n"
                                      "          \"actionName\": \"Go to debug Menu\",\n"
                                      "          \"actionType\": \"DeepLink\",\n"
                                      "          \"defaultFocus\": true,\n"
                                      "          \"parameters\": {\n"
                                      "            \"actionUrl\": \"pssettings:play?function=debug_settings\"\n"
                                      "          }\n"
                                      "        }\n"
                                      "      ]\n"
                                      "    },\n"
                                      "    \"platformViews\": {\n"
                                      "      \"previewDisabled\": {\n"
                                      "        \"viewData\": {\n"
                                      "          \"icon\": {\n"
                                      "            \"type\": \"Predefined\",\n"
                                      "            \"parameters\": {\n"
                                      "              \"icon\": \"download\"\n"
                                      "            }\n"
                                      "          },\n"
                                      "          \"message\": {\n"
                                      "            \"body\": \"notify sample is running\"\n"
                                      "          }\n"
                                      "        }\n"
                                      "      }\n"
                                      "    }\n"
                                      "  },\n"
                                      "  \"createdDateTime\": \"2025-12-14T03:14:51.473Z\",\n"
                                      "  \"localNotificationId\": \"588193127\"\n"
                                      "}";
        
        int buf_sz = strlen(body) + strlen(title) + strlen(toast_tmpl);
        char buf[buf_sz];
        snprintf(buf, buf_sz, toast_tmpl, body, title);    
        return sceNotificationSend(SCE_NOTIFICATION_LOCAL_USER_ID_SYSTEM, true, buf);
    }

int nlog(char* msg) {
    
    
        printf("%s\n", msg);
        return notify(msg);
        
}

int escalate(){
    
    pid_t mypid = getpid();
    kernel_set_ucred_authid(mypid, 0x4800000000000010ULL);
    uint8_t caps[16];
    kernel_get_ucred_caps(mypid, caps);
    caps[7] |= 0x40;
    kernel_set_ucred_caps(mypid, caps);
    setuid(0);
    
    return 0;
}

pid_t find_pid(const char *name) {
    int mib[4] = {1, 14, 8, 0}; size_t sz;
    if (sysctl(mib, 4, 0, &sz, 0, 0)) return -1;
    unsigned char *buf = malloc(sz);
    if (sysctl(mib, 4, buf, &sz, 0, 0)) { free(buf); return -1; }
    pid_t pid = -1; pid_t me = getpid();
    for (unsigned char *p = buf; p < buf + sz;) {
        int rs = *(int *)p; pid_t p2 = *(pid_t *)(p + 72); char *n = (char *)(p + 447);
        if (rs <= 0) break;
        if (!strcmp(name, n) && p2 != me) pid = p2;
        p += rs;
    }
    free(buf); return pid;
}

int pread_mem(pid_t pid, uint64_t addr, void *buf, size_t len) {
    struct ptrace_io_desc iod = { PIOD_READ_D, (void *)addr, buf, len };
    return do_ptrace(PT_IO, pid, (caddr_t)&iod, 0);
}


 int do_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    pid_t mypid = getpid();
    uint8_t caps[16];
    uint64_t authid = kernel_get_ucred_authid(mypid);
    kernel_get_ucred_caps(mypid, caps);
    kernel_set_ucred_authid(mypid, 0x4800000000010003L);
    kernel_set_ucred_caps(mypid, privcaps);
    int ret = (int)__syscall(SYS_ptrace, request, pid, addr, data);
    kernel_set_ucred_authid(mypid, authid);
    kernel_set_ucred_caps(mypid, caps);
    return ret;
}

int ptrace_attach(pid_t pid) {
    if (do_ptrace(PT_ATTACH, pid, 0, 0)) return -1;
    waitpid(pid, 0, 0);
    return 0;
}

void ptrace_detach(pid_t pid) {
    do_ptrace(PT_DETACH, pid, 0, 0);
}

int ptrace_write(pid_t pid, intptr_t addr, const void *buf, size_t len) {
    struct ptrace_io_desc iod = {
        .piod_op = PIOD_WRITE_D,
        .piod_offs = (void *)addr,
        .piod_addr = (void *)buf,
        .piod_len = len,
    };
    return do_ptrace(PT_IO, pid, (caddr_t)&iod, 0);
}

