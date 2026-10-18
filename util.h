#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <stdbool.h>

#ifndef UTIL_H_
#define UTIL_H_

#define SCE_NOTIFICATION_LOCAL_USER_ID_SYSTEM 0xFE


int notify(char* msg);
int nlog(char* msg);
int escalate();
 int do_ptrace(int request, pid_t pid, caddr_t addr, int data);
int ptrace_attach(pid_t pid);
void ptrace_detach(pid_t pid);
int ptrace_write(pid_t pid, intptr_t addr, const void *buf, size_t len);
int pread_mem(pid_t pid, uint64_t addr, void *buf, size_t len);
pid_t find_pid(const char *name);
int toast(char* title, char* body);
int sceNotificationSend(int userId, bool isLogged, const char* payload);

#endif //UTIL_H_
