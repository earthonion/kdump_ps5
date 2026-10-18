include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk


# $(shell) may not exist on your computer
ELFNAME:= $(shell basename $(PWD))

ELF := $(ELFNAME).elf

CFLAGS := -Wall -Werror -g

PAYLOAD_OBJS := $(wildcard payload_files/*.o)

all: $(ELF) icon_svg.h

LDADD := -lSceNotification

SRCS := main.c util.c

$(ELF): $(SRCS) $(PAYLOAD_OBJS) icon_svg.h
	$(CC) $(CFLAGS) -o $@ $(LDADD) $(SRCS) $(PAYLOAD_OBJS)
	

icon_svg.h : icon.svg
	xxd -i icon.svg > icon_svg.h

test:
	nc -q 0 192.168.0.135 9021 < $(ELF)

clean:
	rm -f $(ELF) icon_svg.h
