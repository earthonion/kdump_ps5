#include <stdio.h>
#include <ps5/kernel.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include "util.h"
#include "icon_svg.h"

#define ALIGN_UP(addr, align) (addr + (align - 1)) & ~(align - 1)

#define X86_PG_V  0x01
#define X86_PG_PS 0x80

#define PG_FRAME (0xffffffffff000ul)

//thanks idlesauce!
//https://github.com/ps5-payload-dev/sdk/blob/f5d40f02770e9b0001dd9e18056eca70b3da8b40/crt/kernel_procio.c#L32
int
k_proc_getpaddr(int pid, unsigned long vaddr, unsigned long* paddr,
		     unsigned long* plen) {
  unsigned long table_offset;
  unsigned long table_index;
  unsigned long vmspace;
  unsigned long pml4u;
  unsigned long proc;
  unsigned long cr3;
  unsigned long pte;

  if(!KERNEL_OFFSET_VMSPACE_VM_PMAP) {
    return -1;
  }
  if(!(proc=kernel_get_proc(pid))) {
    return -1;
  }

  if(kernel_copyout(proc + KERNEL_OFFSET_PROC_P_VMSPACE,
		    &vmspace, sizeof(vmspace))) {
    return -1;
  }
  if(kernel_copyout(vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP + 0x20,
		    &pml4u, sizeof(pml4u))) {
    return -1;
  }
  if(kernel_copyout(vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP + 0x28,
		    &cr3, sizeof(cr3))) {
    return -1;
  }

  pte = cr3;
  for(long bitpos=39; bitpos>=12; bitpos-=9) {
    table_index = (vaddr >> bitpos) & ((1ull << 9) - 1);
    table_offset = table_index * 8;
    pte &= PG_FRAME;

    if(kernel_copyout(pml4u-cr3 + table_offset + pte, &pte, sizeof(pte))) {
      return -1;
    }

    // check entry validity
    if(!(pte & X86_PG_V)) {
      return -1;
    }

    // check if the entry is flagged as large or if we reached the last level
    if((pte & X86_PG_PS) || bitpos == 12) {
      *paddr = pte;
      *paddr &= (1ul << 52) - (1ul << bitpos);
      *paddr |= vaddr & ((1ul << bitpos) - 1);
      *plen = (*paddr | ((1ul << bitpos) - 1)) + 1 - *paddr;
      return 0;
    }
  }

  return -1;
}


void find_size(size_t *ksize) {
  char data[0x50];

  uintptr_t vaddr = ALIGN_UP(KERNEL_ADDRESS_ALLPROC, 0x1000);
  while (1) {
    kernel_copyout(vaddr, data, sizeof(data));

    // Module info is at the end.
    if (strcmp(data + 0x08, "kernel") == 0 &&
        strcmp(data + 0x18, "elf kernel") == 0) {

      *ksize = *(uintptr_t *)(data + 0x40);
      break;
    }

    vaddr += 0x1000;
  }

  //log("find kmdp completed !!");
}

int main() {
    
    
    char buf[0x4000];
    char *dest_path = NULL;
    //intptr_t data = KERNEL_ADDRESS_DATA_BASE;
    
    FILE *icon;
    
    icon = fopen("/system_tmp/icon.svg", "wb");
    size_t icon_sz = fwrite(&icon_svg, sizeof(icon_svg[0]), icon_svg_len, icon);
    printf("wrote %zu bytes to /system_tmp/icon.svg...\n", icon_sz);
    fclose(icon);
    
    toast("kdump","dumping kernel...");
    
    kernel_set_ucred_authid(getpid(), 0x4800000000000007);
    kernel_set_proc_rootdir(getpid(), kernel_get_root_vnode());
    
    uint16_t fw =  kernel_get_fw_version() >> 16;
    printf("Firmware Version: %04x\n", fw);
    notify("dumping kernel to usb. please wait...");
    
    size_t ksize = 0;
    find_size(&ksize);
    printf("ksize: %lx\n", ksize);
    
    asprintf(&dest_path, "/mnt/usb0/PS5/kernel_%04x.bin", fw);
    
    int dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    
    uint64_t end = 0;
    for(uint64_t vaddr = KERNEL_ADDRESS_TEXT_BASE;;vaddr += sizeof(buf)){
        

        uint64_t kend = KERNEL_ADDRESS_TEXT_BASE + ksize;
        if (vaddr > kend){
            break;
        }
        if(kernel_copyout(vaddr, &buf, sizeof(buf))){
            break;
        }
        if(write(dest_fd, buf, sizeof(buf)) != sizeof(buf)){
            perror("write");
            break;
        }
        //printf("addr: %lx\n", vaddr);
        end = vaddr;
        
    }
    close(dest_fd);
    free(dest_path);
    dest_path = NULL;
    
    
    printf("kernel size: %lumb\n", (end - KERNEL_ADDRESS_TEXT_BASE)/(1024*1024));//mb
    notify("done!");
    
    
    return 0;
    
}
