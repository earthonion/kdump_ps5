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

//https://github.com/ufm42/kexp/blob/00623847b4974a769e3111272964d2e672a5e8ce/src/kernel.c#L97
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
