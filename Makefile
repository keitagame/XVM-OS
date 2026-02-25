# XVM-OS Makefile
CC      = gcc
LD      = ld
OBJCOPY = objcopy
QEMU    = qemu-system-i386

CFLAGS  = -m32 -ffreestanding -fno-pie -fno-pic -nostdlib -nostdinc \
          -fno-stack-protector -O2 -std=gnu99 -Wall -Wextra

LDFLAGS = -m elf_i386 -T link.ld

TARGET  = xvm_os

all: $(TARGET).bin

$(TARGET).o: $(TARGET).c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET).elf: $(TARGET).o link.ld
	$(LD) $(LDFLAGS) -o $@ $(TARGET).o

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

run: $(TARGET).bin
	$(QEMU) -kernel $(TARGET).bin -m 64 -display sdl

run-text: $(TARGET).bin
	$(QEMU) -kernel $(TARGET).elf -m 64 -display curses -serial stdio

run-vnc: $(TARGET).bin
	$(QEMU) -kernel $(TARGET).bin -m 64 -vnc :0

debug: $(TARGET).bin
	$(QEMU) -kernel $(TARGET).bin -m 64 -s -S -display sdl &
	gdb -ex "target remote :1234" \
	    -ex "symbol-file $(TARGET).elf" \
	    -ex "break kmain"

clean:
	rm -f $(TARGET).o $(TARGET).elf $(TARGET).bin

iso: $(TARGET).bin
	mkdir -p iso/boot/grub
	cp $(TARGET).bin iso/boot/
	echo 'menuentry "XVM-OS" { multiboot /boot/xvm_os.bin; boot }' \
	    > iso/boot/grub/grub.cfg
	grub-mkrescue -o $(TARGET).iso iso/
	$(QEMU) -cdrom $(TARGET).iso -m 64

.PHONY: all run run-text run-vnc debug clean iso
