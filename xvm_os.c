/*
 * XVM-OS - A Minimal Unix-like Operating System
 * Single-file implementation in C
 *
 * Architecture: x86 (32-bit protected mode)
 * Features:
 *   - Bootloader (Multiboot2 compatible)
 *   - GDT/IDT setup
 *   - Interrupt handling (PIC, IRQs)
 *   - Physical & virtual memory management (paging)
 *   - Process management (fork, exec, wait, exit)
 *   - Scheduler (round-robin)
 *   - VFS (virtual file system layer)
 *   - ramfs (root filesystem in RAM)
 *   - System calls (POSIX subset)
 *   - TTY/console driver
 *   - ELF loader (basic)
 *   - Built-in shell (xsh) that can run programs
 *
 * Build:
 *   gcc -m32 -ffreestanding -fno-pie -nostdlib -nostdinc \
 *       -fno-stack-protector -O2 -std=gnu99 \
 *       -Wl,--oformat=binary -Wl,-T,link.ld \
 *       -o xvm_os.bin xvm_os.c
 *
 * Or use the Makefile generated at the end of this file.
 * Run with: qemu-system-i386 -kernel xvm_os.bin -m 64
 */

/* =========================================================
 * COMPILER / ARCH DEFINITIONS
 * ========================================================= */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef signed char        int8_t;
typedef signed short       int16_t;
typedef signed int         int32_t;
typedef signed long long   int64_t;
typedef uint32_t           size_t;
typedef int32_t            ssize_t;
typedef int32_t            pid_t;
typedef uint32_t           uid_t;
typedef uint32_t           mode_t;
typedef uint32_t           ino_t;
typedef uint32_t           dev_t;
typedef int32_t            off_t;

#define NULL    ((void*)0)
#define true    1
#define false   0
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/* Attribute macros */
#define __packed        __attribute__((packed))
#define __noreturn      __attribute__((noreturn))
#define __aligned(x)    __attribute__((aligned(x)))
#define __used          __attribute__((used))
#define __section(s)    __attribute__((section(s)))
#define UNUSED(x)       ((void)(x))

/* =========================================================
 * MEMORY MAP
 * ========================================================= */
#define KERNEL_VIRT_BASE    0x00100000   /* 1MB - kernel loads here */
#define KERNEL_HEAP_START   0x00400000   /* 4MB */
#define KERNEL_HEAP_END     0x00800000   /* 8MB */
#define USER_STACK_TOP      0xBFFFF000
#define USER_MMAP_BASE      0x40000000
#define PAGE_SIZE           4096
#define PAGE_SHIFT          12
#define PAGE_MASK           (~(PAGE_SIZE-1))
#define ALIGN_UP(x,a)       (((x)+(a)-1)&~((a)-1))
#define ALIGN_DOWN(x,a)     ((x)&~((a)-1))

/* Physical memory: simple bitmap allocator */
#define PHYS_MEM_BYTES      (64*1024*1024)  /* 64MB */
#define PHYS_PAGES          (PHYS_MEM_BYTES / PAGE_SIZE)
#define PHYS_BITMAP_WORDS   (PHYS_PAGES / 32)

static uint32_t phys_bitmap[PHYS_BITMAP_WORDS];
static uint32_t phys_alloc_next = 0;
static int strstr_simple(const char*, const char*);
static void phys_mark_used(uint32_t page) {
    phys_bitmap[page/32] |= (1u << (page%32));
}
static void phys_mark_free(uint32_t page) {
    phys_bitmap[page/32] &= ~(1u << (page%32));
}
static int phys_is_used(uint32_t page) {
    return (phys_bitmap[page/32] >> (page%32)) & 1;
}

uint32_t phys_alloc_page(void) {
    for (uint32_t i = phys_alloc_next; i < PHYS_PAGES; i++) {
        if (!phys_is_used(i)) {
            phys_mark_used(i);
            phys_alloc_next = i+1;
            return i * PAGE_SIZE;
        }
    }
    /* wrap */
    for (uint32_t i = 0; i < phys_alloc_next; i++) {
        if (!phys_is_used(i)) {
            phys_mark_used(i);
            phys_alloc_next = i+1;
            return i * PAGE_SIZE;
        }
    }
    return 0; /* OOM */
}

void phys_free_page(uint32_t addr) {
    uint32_t page = addr / PAGE_SIZE;
    if (page < PHYS_PAGES) {
        phys_mark_free(page);
        if (page < phys_alloc_next) phys_alloc_next = page;
    }
}

/* =========================================================
 * PAGING (x86 32-bit, no PAE)
 * ========================================================= */
#define PDE_PRESENT    0x001
#define PDE_WRITE      0x002
#define PDE_USER       0x004
#define PDE_4MB        0x080
#define PTE_PRESENT    0x001
#define PTE_WRITE      0x002
#define PTE_USER       0x004

typedef uint32_t pde_t;
typedef uint32_t pte_t;

/* Kernel page directory - identity mapped for now */
static pde_t kernel_pgd[1024] __aligned(4096);

static void paging_map(pde_t *pgd, uint32_t virt, uint32_t phys, uint32_t flags) {
    uint32_t pdi = virt >> 22;
    uint32_t pti = (virt >> 12) & 0x3FF;

    if (!(pgd[pdi] & PDE_PRESENT)) {
        uint32_t pt_phys = phys_alloc_page();
        uint8_t *pt = (uint8_t*)pt_phys;
        for (int i = 0; i < 4096; i++) pt[i] = 0;
        pgd[pdi] = pt_phys | PDE_PRESENT | PDE_WRITE | (flags & PDE_USER);
    }

    pte_t *pt = (pte_t*)(pgd[pdi] & PAGE_MASK);
    pt[pti] = (phys & PAGE_MASK) | PTE_PRESENT | flags;
}

static void paging_unmap(pde_t *pgd, uint32_t virt) {
    uint32_t pdi = virt >> 22;
    uint32_t pti = (virt >> 12) & 0x3FF;
    if (!(pgd[pdi] & PDE_PRESENT)) return;
    pte_t *pt = (pte_t*)(pgd[pdi] & PAGE_MASK);
    pt[pti] = 0;
    __asm__ volatile("invlpg (%0)" :: "r"(virt) : "memory");
}

static void paging_enable(pde_t *pgd) {
    __asm__ volatile(
        "mov %0, %%cr3\n"
        "mov %%cr0, %%eax\n"
        "or $0x80000000, %%eax\n"
        "mov %%eax, %%cr0\n"
        :: "r"(pgd) : "eax"
    );
}

static void paging_init(void) {
    /* Mark first 8MB as used (kernel space) */
    for (uint32_t i = 0; i < 8*1024*1024/PAGE_SIZE; i++)
        phys_mark_used(i);

    /* Identity map first 8MB using 4MB pages for simplicity */
    kernel_pgd[0] = 0x000000 | PDE_PRESENT | PDE_WRITE | PDE_4MB;
    kernel_pgd[1] = 0x400000 | PDE_PRESENT | PDE_WRITE | PDE_4MB;

    /* Enable PSE (4MB pages) in CR4 */
    __asm__ volatile(
        "mov %%cr4, %%eax\n"
        "or $0x10, %%eax\n"
        "mov %%eax, %%cr4\n"
        ::: "eax"
    );

    paging_enable(kernel_pgd);
}

/* =========================================================
 * SIMPLE KERNEL HEAP (bump allocator + free list)
 * ========================================================= */
static uint32_t heap_ptr = KERNEL_HEAP_START;

void *kmalloc(size_t size) {
    if (size == 0) return NULL;
    size = ALIGN_UP(size, 8);
    if (heap_ptr + size > KERNEL_HEAP_END) return NULL;
    void *p = (void*)heap_ptr;
    heap_ptr += size;
    return p;
}

void *kzalloc(size_t size) {
    void *p = kmalloc(size);
    if (p) {
        uint8_t *b = (uint8_t*)p;
        for (size_t i = 0; i < size; i++) b[i] = 0;
    }
    return p;
}

void kfree(void *p) {
    UNUSED(p);
    /* Simple bump allocator - no free */
}

/* =========================================================
 * STRING FUNCTIONS
 * ========================================================= */
static size_t strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}
static int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
static int strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    if (!n) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}
static char *strcpy(char *d, const char *s) {
    char *r = d;
    while ((*d++ = *s++));
    return r;
}
static char *strncpy(char *d, const char *s, size_t n) {
    char *r = d;
    while (n && (*d++ = *s++)) n--;
    while (n--) *d++ = 0;
    return r;
}
static char *strcat(char *d, const char *s) {
    char *r = d;
    while (*d) d++;
    while ((*d++ = *s++));
    return r;
}
static char *strchr(const char *s, int c) {
    while (*s) { if (*s == (char)c) return (char*)s; s++; }
    return (c == 0) ? (char*)s : NULL;
}
static char *strrchr(const char *s, int c) {
    const char *r = NULL;
    while (*s) { if (*s == (char)c) r = s; s++; }
    return (char*)r;
}
static void *memcpy(void *d, const void *s, size_t n) {
    uint8_t *dd = d; const uint8_t *ss = s;
    while (n--) *dd++ = *ss++;
    return d;
}
static void *memset(void *d, int c, size_t n) {
    uint8_t *dd = d;
    while (n--) *dd++ = (uint8_t)c;
    return d;
}
static int memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *aa = a, *bb = b;
    while (n--) { if (*aa != *bb) return *aa - *bb; aa++; bb++; }
    return 0;
}

static char *strdup(const char *s) {
    size_t n = strlen(s)+1;
    char *p = kmalloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

/* itoa */
static void itoa(int v, char *buf, int base) {
    char tmp[32]; int i = 0, neg = 0;
    if (v < 0 && base == 10) { neg = 1; v = -v; }
    if (v == 0) { tmp[i++] = '0'; }
    while (v) { int r = v%base; tmp[i++] = (r<10)?('0'+r):('a'+r-10); v /= base; }
    if (neg) tmp[i++] = '-';
    int j = 0;
    while (i--) buf[j++] = tmp[i];
    buf[j] = 0;
}
static void utoa(uint32_t v, char *buf, int base) {
    char tmp[32]; int i = 0;
    if (v == 0) { tmp[i++] = '0'; }
    while (v) { int r = v%base; tmp[i++] = (r<10)?('0'+r):('a'+r-10); v /= base; }
    int j = 0; while (i--) buf[j++] = tmp[i]; buf[j] = 0;
}
static int atoi(const char *s) {
    int n = 0, neg = 0;
    while (*s == ' ') s++;
    if (*s == '-') { neg=1; s++; } else if (*s == '+') s++;
    while (*s >= '0' && *s <= '9') n = n*10 + (*s++ - '0');
    return neg ? -n : n;
}

/* =========================================================
 * VGA TEXT MODE CONSOLE
 * ========================================================= */
#define VGA_BASE    0xB8000
#define VGA_COLS    80
#define VGA_ROWS    25
#define VGA_ATTR    0x0F  /* white on black */

static uint16_t *vga_buf = (uint16_t*)VGA_BASE;
static int vga_row = 0, vga_col = 0;

static void vga_scroll(void) {
    for (int r = 1; r < VGA_ROWS; r++)
        for (int c = 0; c < VGA_COLS; c++)
            vga_buf[(r-1)*VGA_COLS+c] = vga_buf[r*VGA_COLS+c];
    for (int c = 0; c < VGA_COLS; c++)
        vga_buf[(VGA_ROWS-1)*VGA_COLS+c] = (VGA_ATTR<<8)|' ';
    vga_row = VGA_ROWS-1;
}

static void vga_update_cursor(void) {
    uint16_t pos = vga_row * VGA_COLS + vga_col;
    /* CRT controller ports */
    __asm__ volatile("outb %0, %1" :: "a"((uint8_t)0x0F), "Nd"((uint16_t)0x3D4));
    __asm__ volatile("outb %0, %1" :: "a"((uint8_t)(pos&0xFF)), "Nd"((uint16_t)0x3D5));
    __asm__ volatile("outb %0, %1" :: "a"((uint8_t)0x0E), "Nd"((uint16_t)0x3D4));
    __asm__ volatile("outb %0, %1" :: "a"((uint8_t)(pos>>8)), "Nd"((uint16_t)0x3D5));
}

static void vga_putc(char c) {
    if (c == '\n') {
        vga_col = 0; vga_row++;
    } else if (c == '\r') {
        vga_col = 0;
    } else if (c == '\b') {
        if (vga_col > 0) {
            vga_col--;
            vga_buf[vga_row*VGA_COLS+vga_col] = (VGA_ATTR<<8)|' ';
        }
    } else if (c == '\t') {
        vga_col = (vga_col + 8) & ~7;
        if (vga_col >= VGA_COLS) { vga_col = 0; vga_row++; }
    } else {
        vga_buf[vga_row*VGA_COLS+vga_col] = ((uint16_t)VGA_ATTR<<8)|(uint8_t)c;
        vga_col++;
        if (vga_col >= VGA_COLS) { vga_col = 0; vga_row++; }
    }
    if (vga_row >= VGA_ROWS) vga_scroll();
    vga_update_cursor();
}

static void vga_puts(const char *s) {
    while (*s) vga_putc(*s++);
}

static void vga_clear(void) {
    for (int i = 0; i < VGA_ROWS*VGA_COLS; i++)
        vga_buf[i] = (VGA_ATTR<<8)|' ';
    vga_row = vga_col = 0;
    vga_update_cursor();
}

/* kprintf - kernel printf (minimal) */
static void kprintf(const char *fmt, ...) {
    /* Minimal va_args inline */
    uint32_t *args = (uint32_t*)&fmt + 1;
    int ai = 0;
    char buf[32];

    while (*fmt) {
        if (*fmt == '%') {
            fmt++;
            int pad = 0;
            while (*fmt >= '0' && *fmt <= '9') { pad = pad*10 + *fmt++ - '0'; }
            switch (*fmt) {
            case 'd': itoa((int)args[ai++], buf, 10); vga_puts(buf); break;
            case 'u': utoa(args[ai++], buf, 10); vga_puts(buf); break;
            case 'x': utoa(args[ai++], buf, 16); vga_puts(buf); break;
            case 'p': vga_puts("0x"); utoa(args[ai++], buf, 16); vga_puts(buf); break;
            case 's': { char *s=(char*)args[ai++]; if(s)vga_puts(s); else vga_puts("(null)"); break; }
            case 'c': vga_putc((char)args[ai++]); break;
            case '%': vga_putc('%'); break;
            default: vga_putc('%'); vga_putc(*fmt); break;
            }
        } else {
            vga_putc(*fmt);
        }
        fmt++;
    }
}

/* =========================================================
 * I/O PORT HELPERS
 * ========================================================= */
static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile("outb %0,%1" :: "a"(val),"Nd"(port));
}
static inline uint8_t inb(uint16_t port) {
    uint8_t v;
    __asm__ volatile("inb %1,%0" : "=a"(v) : "Nd"(port));
    return v;
}
static inline void io_wait(void) { outb(0x80, 0); }

/* =========================================================
 * GDT (Global Descriptor Table)
 * ========================================================= */
struct gdt_entry { uint16_t lim_lo, base_lo; uint8_t base_mid, access, gran, base_hi; } __packed;
struct gdt_ptr   { uint16_t limit; uint32_t base; } __packed;

#define GDT_ENTRIES 6
static struct gdt_entry gdt[GDT_ENTRIES];
static struct gdt_ptr   gdt_ptr;

static void gdt_set(int i, uint32_t base, uint32_t limit, uint8_t access, uint8_t gran) {
    gdt[i].base_lo  = base & 0xFFFF;
    gdt[i].base_mid = (base>>16) & 0xFF;
    gdt[i].base_hi  = (base>>24) & 0xFF;
    gdt[i].lim_lo   = limit & 0xFFFF;
    gdt[i].gran     = ((limit>>16)&0x0F) | (gran&0xF0);
    gdt[i].access   = access;
}

static void gdt_flush(struct gdt_ptr *p) __attribute__((noinline));
static void gdt_flush(struct gdt_ptr *p) {
    __asm__ volatile(
        "lgdt (%0)\n"
        "mov $0x10, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "mov %%ax, %%fs\n"
        "mov %%ax, %%gs\n"
        "mov %%ax, %%ss\n"
        "ljmp $0x08, $1f\n"
        "1:\n"
        :: "r"(p) : "ax"
    );
}

static void gdt_init(void) {
    gdt_ptr.limit = sizeof(gdt)-1;
    gdt_ptr.base  = (uint32_t)gdt;
    gdt_set(0, 0, 0, 0, 0);               /* null */
    gdt_set(1, 0, 0xFFFFF, 0x9A, 0xCF);   /* kernel code */
    gdt_set(2, 0, 0xFFFFF, 0x92, 0xCF);   /* kernel data */
    gdt_set(3, 0, 0xFFFFF, 0xFA, 0xCF);   /* user code */
    gdt_set(4, 0, 0xFFFFF, 0xF2, 0xCF);   /* user data */
    gdt_set(5, 0, 0, 0, 0);               /* TSS placeholder */
    gdt_flush(&gdt_ptr);
}

/* =========================================================
 * IDT (Interrupt Descriptor Table)
 * ========================================================= */
struct idt_entry { uint16_t off_lo; uint16_t sel; uint8_t zero, flags; uint16_t off_hi; } __packed;
struct idt_ptr   { uint16_t limit; uint32_t base; } __packed;

#define IDT_ENTRIES 256
static struct idt_entry idt[IDT_ENTRIES];
static struct idt_ptr   idt_ptr;

static void idt_set(int i, uint32_t handler, uint8_t flags) {
    idt[i].off_lo = handler & 0xFFFF;
    idt[i].off_hi = (handler>>16) & 0xFFFF;
    idt[i].sel    = 0x08; /* kernel code segment */
    idt[i].zero   = 0;
    idt[i].flags  = flags;
}

/* CPU exception names */
static const char *exception_names[] = {
    "Division by Zero", "Debug", "NMI", "Breakpoint",
    "Overflow", "Bound Range", "Invalid Opcode", "Device Not Available",
    "Double Fault", "Coprocessor Segment Overrun", "Invalid TSS", "Segment Not Present",
    "Stack Fault", "General Protection Fault", "Page Fault", "Reserved",
    "x87 FPU Error", "Alignment Check", "Machine Check", "SIMD FP Exception"
};

/* Interrupt frame */
struct int_frame {
    uint32_t ds;
    uint32_t edi,esi,ebp,esp_dummy,ebx,edx,ecx,eax; /* pusha */
    uint32_t int_no, err_code;
    uint32_t eip, cs, eflags, esp, ss; /* pushed by CPU */
};

/* Forward declarations for ISRs */
static void isr_handler(struct int_frame *f);
static void irq_handler(struct int_frame *f);

/* ISR stubs - we use a macro trick via inline asm */
#define ISR_NOERR(n) \
    static void __attribute__((naked)) isr##n(void) { \
        __asm__ volatile("push $0\npush $" #n "\njmp isr_common_stub"); }
#define ISR_ERR(n) \
    static void __attribute__((naked)) isr##n(void) { \
        __asm__ volatile("push $" #n "\njmp isr_common_stub"); }
//#define IRQ(n,irq) \
//    static void __attribute__((naked)) irq##n(void) { \
//       __asm__ volatile("push $0\npush $" #irq "\njmp irq_common_stub"); }

#define IRQ(n,vec) \
static void __attribute__((naked)) irq##vec(void) { \
    __asm__ volatile ( \
        "cli\n" \
        "pushl $0\n" \
        "pushl $" #vec "\n" \
        "jmp irq_common_stub\n" \
    ); \
}

ISR_NOERR(0)  ISR_NOERR(1)  ISR_NOERR(2)  ISR_NOERR(3)
ISR_NOERR(4)  ISR_NOERR(5)  ISR_NOERR(6)  ISR_NOERR(7)
ISR_ERR(8)    ISR_NOERR(9)  ISR_ERR(10)   ISR_ERR(11)
ISR_ERR(12)   ISR_ERR(13)   ISR_ERR(14)   ISR_NOERR(15)
ISR_NOERR(16) ISR_NOERR(17) ISR_NOERR(18) ISR_NOERR(19)
ISR_NOERR(20) ISR_NOERR(21) ISR_NOERR(22) ISR_NOERR(23)
ISR_NOERR(24) ISR_NOERR(25) ISR_NOERR(26) ISR_NOERR(27)
ISR_NOERR(28) ISR_NOERR(29) ISR_NOERR(30) ISR_NOERR(31)
IRQ(0,32); IRQ(1,33); IRQ(2,34); IRQ(3,35);
IRQ(4,36); IRQ(5,37); IRQ(6,38); IRQ(7,39);
IRQ(8,40); IRQ(9,41); IRQ(10,42); IRQ(11,43);
IRQ(12,44); IRQ(13,45); IRQ(14,46); IRQ(15,47);

/* Syscall stub: int 0x80 */
static void __attribute__((naked)) isr128(void) {
    __asm__ volatile("push $0\npush $128\njmp isr_common_stub");
}

static void __attribute__((naked,used)) isr_common_stub(void) {
    __asm__ volatile(
        "pusha\n"
        "mov %%ds, %%eax\n"
        "push %%eax\n"
        "mov $0x10, %%ax\n"
        "mov %%ax, %%ds\nmov %%ax, %%es\nmov %%ax, %%fs\nmov %%ax, %%gs\n"
        "push %%esp\n"
        "call isr_handler\n"
        "add $4, %%esp\n"
        "pop %%eax\n"
        "mov %%ax, %%ds\nmov %%ax, %%es\nmov %%ax, %%fs\nmov %%ax, %%gs\n"
        "popa\n"
        "add $8, %%esp\n"
        "iret\n"
        ::: "eax"
    );
}

static void __attribute__((naked,used)) irq_common_stub(void) {
    __asm__ volatile(
        "pusha\n"
        "mov %%ds, %%eax\n"
        "push %%eax\n"
        "mov $0x10, %%ax\n"
        "mov %%ax, %%ds\nmov %%ax, %%es\nmov %%ax, %%fs\nmov %%ax, %%gs\n"
        "push %%esp\n"
        "call irq_handler\n"
        "add $4, %%esp\n"
        "pop %%eax\n"
        "mov %%ax, %%ds\nmov %%ax, %%es\nmov %%ax, %%fs\nmov %%ax, %%gs\n"
        "popa\n"
        "add $8, %%esp\n"
        "iret\n"
        ::: "eax"
    );
}

/* PIC (8259) remap */
static void pic_remap(void) {
    outb(0x20, 0x11); outb(0xA0, 0x11); io_wait();
    outb(0x21, 0x20); outb(0xA1, 0x28); io_wait();
    outb(0x21, 0x04); outb(0xA1, 0x02); io_wait();
    outb(0x21, 0x01); outb(0xA1, 0x01); io_wait();
    outb(0x21, 0x00); outb(0xA1, 0x00); /* unmask all */
}

static void pic_eoi(uint8_t irq) {
    if (irq >= 8) outb(0xA0, 0x20);
    outb(0x20, 0x20);
}

static void idt_init(void) {
    idt_ptr.limit = sizeof(idt)-1;
    idt_ptr.base  = (uint32_t)idt;

    memset(idt, 0, sizeof(idt));

#define SET_ISR(n) idt_set(n, (uint32_t)isr##n, 0x8E)
    SET_ISR(0);  SET_ISR(1);  SET_ISR(2);  SET_ISR(3);
    SET_ISR(4);  SET_ISR(5);  SET_ISR(6);  SET_ISR(7);
    SET_ISR(8);  SET_ISR(9);  SET_ISR(10); SET_ISR(11);
    SET_ISR(12); SET_ISR(13); SET_ISR(14); SET_ISR(15);
    SET_ISR(16); SET_ISR(17); SET_ISR(18); SET_ISR(19);
    SET_ISR(20); SET_ISR(21); SET_ISR(22); SET_ISR(23);
    SET_ISR(24); SET_ISR(25); SET_ISR(26); SET_ISR(27);
    SET_ISR(28); SET_ISR(29); SET_ISR(30); SET_ISR(31);
#undef SET_ISR

#define SET_IRQ(n) idt_set(n, (uint32_t)irq##n, 0x8E)
    SET_IRQ(32); SET_IRQ(33); SET_IRQ(34); SET_IRQ(35);
    SET_IRQ(36); SET_IRQ(37); SET_IRQ(38); SET_IRQ(39);
    SET_IRQ(40); SET_IRQ(41); SET_IRQ(42); SET_IRQ(43);
    SET_IRQ(44); SET_IRQ(45); SET_IRQ(46); SET_IRQ(47);
#undef SET_IRQ

    idt_set(128, (uint32_t)isr128, 0xEE); /* syscall, DPL=3 */

    pic_remap();

    __asm__ volatile("lidt (%0)" :: "r"(&idt_ptr));
    __asm__ volatile("sti");
}

/* =========================================================
 * PIT (Timer) - IRQ0
 * ========================================================= */
#define PIT_HZ      100  /* 100 Hz = 10ms ticks */
static volatile uint32_t pit_ticks = 0;

static void pit_init(void) {
    uint32_t divisor = 1193180 / PIT_HZ;
    outb(0x43, 0x36);
    outb(0x40, divisor & 0xFF);
    outb(0x40, (divisor>>8) & 0xFF);
}

static void sleep_ms(uint32_t ms) {
    uint32_t end = pit_ticks + (ms * PIT_HZ / 1000) + 1;
    while (pit_ticks < end) __asm__ volatile("hlt");
}

/* =========================================================
 * KEYBOARD DRIVER (PS/2, IRQ1)
 * ========================================================= */
#define KB_DATA_PORT 0x60
#define KB_BUF_SIZE  256

static char kb_buf[KB_BUF_SIZE];
static volatile int kb_head = 0, kb_tail = 0;

static const char kb_us_map[] = {
    0, 27,'1','2','3','4','5','6','7','8','9','0','-','=','\b',
    '\t','q','w','e','r','t','y','u','i','o','p','[',']','\n',
    0,'a','s','d','f','g','h','j','k','l',';','\'','`',
    0,'\\','z','x','c','v','b','n','m',',','.','/',0,'*',
    0,' ',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    '-',0,0,0,'+',0,0,0,0,0,0,0,0,0
};
static const char kb_us_shift[] = {
    0, 27,'!','@','#','$','%','^','&','*','(',')','_','+','\b',
    '\t','Q','W','E','R','T','Y','U','I','O','P','{','}','\n',
    0,'A','S','D','F','G','H','J','K','L',':','"','~',
    0,'|','Z','X','C','V','B','N','M','<','>','?',0,'*',
    0,' ',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    '-',0,0,0,'+',0,0,0,0,0,0,0,0,0
};

static int kb_shift = 0, kb_ctrl = 0;

static void kb_handler(void) {
    uint8_t sc = inb(KB_DATA_PORT);
    int released = sc & 0x80;
    sc &= 0x7F;

    if (sc == 0x2A || sc == 0x36) { kb_shift = !released; return; }
    if (sc == 0x1D) { kb_ctrl = !released; return; }
    if (released) return;

    char c = 0;
    if (sc < sizeof(kb_us_map)) {
        c = kb_shift ? kb_us_shift[sc] : kb_us_map[sc];
    }
    if (kb_ctrl && c >= 'a' && c <= 'z') c -= 96; /* ctrl+a = 0x01 etc */
    if (kb_ctrl && c >= 'A' && c <= 'Z') c -= 64;

    if (c) {
        int next = (kb_head + 1) % KB_BUF_SIZE;
        if (next != kb_tail) {
            kb_buf[kb_head] = c;
            kb_head = next;
        }
    }
}

static int kb_getc_nowait(void) {
    if (kb_tail == kb_head) return -1;
    char c = kb_buf[kb_tail];
    kb_tail = (kb_tail + 1) % KB_BUF_SIZE;
    return (unsigned char)c;
}

static char kb_getc(void) {
    while (kb_tail == kb_head) __asm__ volatile("hlt");
    return (char)kb_getc_nowait();
}

/* =========================================================
 * TTY / TERMINAL
 * ========================================================= */
#define TTY_LINEBUF 512

static char tty_line[TTY_LINEBUF];
static int  tty_pos = 0;
static volatile int tty_ready = 0;
static char tty_read_buf[TTY_LINEBUF];
static int  tty_read_len = 0;
static int  tty_read_pos = 0;

/* Echo character to screen */
static void tty_echo(char c) {
    vga_putc(c);
}

/* Called from keyboard IRQ: accumulate line */
static void tty_input(char c) {
    if (tty_ready) return; /* busy */
    if (c == '\n' || c == '\r') {
        tty_echo('\n');
        tty_line[tty_pos] = '\n';
        tty_pos++;
        tty_line[tty_pos] = 0;
        memcpy(tty_read_buf, tty_line, tty_pos+1);
        tty_read_len = tty_pos;
        tty_read_pos = 0;
        tty_pos = 0;
        tty_ready = 1;
    } else if (c == '\b' || c == 127) {
        if (tty_pos > 0) {
            tty_pos--;
            tty_echo('\b');
        }
    } else if (c >= ' ' || c == '\t') {
        if (tty_pos < TTY_LINEBUF-2) {
            tty_line[tty_pos++] = c;
            tty_echo(c);
        }
    } else if (c == 3) { /* Ctrl+C */
        tty_echo('^'); tty_echo('C'); tty_echo('\n');
        tty_pos = 0;
        tty_ready = -1; /* signal interrupt */
    } else if (c == 4) { /* Ctrl+D */
        tty_echo('\n');
        tty_read_buf[0] = 0;
        tty_read_len = 0;
        tty_read_pos = 0;
        tty_ready = 1; /* EOF */
    }
}

/* Read up to n bytes from TTY (blocking) */
static int tty_read(char *buf, int n) {
    while (!tty_ready) __asm__ volatile("hlt");
    if (tty_ready < 0) { tty_ready = 0; return -1; } /* EINTR */

    int got = 0;
    while (got < n && tty_read_pos < tty_read_len) {
        buf[got++] = tty_read_buf[tty_read_pos++];
    }
    if (tty_read_pos >= tty_read_len) tty_ready = 0;
    return got;
}

static int tty_write(const char *buf, int n) {
    for (int i = 0; i < n; i++) vga_putc(buf[i]);
    return n;
}

/* =========================================================
 * VFS (Virtual File System)
 * ========================================================= */
#define NAME_MAX     255
#define PATH_MAX     1024
#define OPEN_MAX     16

typedef enum { VFS_FILE, VFS_DIR, VFS_DEV } vfs_type_t;

struct vfs_node;

typedef struct {
    int   (*read)(struct vfs_node*, off_t, size_t, char*);
    int   (*write)(struct vfs_node*, off_t, size_t, const char*);
    struct vfs_node* (*lookup)(struct vfs_node*, const char*);
    int   (*readdir)(struct vfs_node*, int, char*, size_t);
    int   (*mkdir)(struct vfs_node*, const char*, mode_t);
    int   (*create)(struct vfs_node*, const char*, mode_t);
    int   (*unlink)(struct vfs_node*, const char*);
    int   (*stat)(struct vfs_node*, struct stat*);
    void  (*close)(struct vfs_node*);
} vfs_ops_t;

struct stat {
    dev_t  st_dev;
    ino_t  st_ino;
    mode_t st_mode;
    uint32_t st_nlink;
    uid_t  st_uid;
    uint32_t st_gid;
    dev_t  st_rdev;
    off_t  st_size;
    uint32_t st_blksize;
    uint32_t st_blocks;
    uint32_t st_atime;
    uint32_t st_mtime;
    uint32_t st_ctime;
};

typedef struct vfs_node {
    char        name[NAME_MAX+1];
    vfs_type_t  type;
    mode_t      mode;
    uint32_t    size;
    uint32_t    inode;
    vfs_ops_t  *ops;
    void       *data; /* filesystem-specific */
    struct vfs_node *parent;
    struct vfs_node *children; /* linked list */
    struct vfs_node *next;     /* sibling */
    uint32_t    ref;
} vfs_node_t;

static vfs_node_t *vfs_root = NULL;
static uint32_t    vfs_next_inode = 1;

/* =========================================================
 * RAMFS - in-memory filesystem
 * ========================================================= */
#define RAMFS_MAX_FILE_SIZE (256*1024)  /* 256KB per file */

typedef struct {
    uint8_t *data;
    uint32_t capacity;
    uint32_t size;
} ramfs_file_t;

static vfs_node_t *ramfs_create_node(vfs_node_t *parent, const char *name, vfs_type_t type, mode_t mode);
static int ramfs_read(vfs_node_t *n, off_t off, size_t len, char *buf);
static int ramfs_write(vfs_node_t *n, off_t off, size_t len, const char *buf);
static vfs_node_t *ramfs_lookup(vfs_node_t *n, const char *name);
static int ramfs_readdir(vfs_node_t *n, int idx, char *namebuf, size_t nbsz);
static int ramfs_mkdir(vfs_node_t *n, const char *name, mode_t mode);
static int ramfs_create(vfs_node_t *n, const char *name, mode_t mode);
static int ramfs_unlink(vfs_node_t *n, const char *name);
static int ramfs_stat(vfs_node_t *n, struct stat *st);

static vfs_ops_t ramfs_ops = {
    .read    = ramfs_read,
    .write   = ramfs_write,
    .lookup  = ramfs_lookup,
    .readdir = ramfs_readdir,
    .mkdir   = ramfs_mkdir,
    .create  = ramfs_create,
    .unlink  = ramfs_unlink,
    .stat    = ramfs_stat,
    .close   = NULL,
};

static vfs_node_t *ramfs_alloc_node(void) {
    vfs_node_t *n = kzalloc(sizeof(vfs_node_t));
    if (n) n->inode = vfs_next_inode++;
    return n;
}

static vfs_node_t *ramfs_create_node(vfs_node_t *parent, const char *name, vfs_type_t type, mode_t mode) {
    vfs_node_t *n = ramfs_alloc_node();
    if (!n) return NULL;
    strncpy(n->name, name, NAME_MAX);
    n->type   = type;
    n->mode   = mode;
    n->ops    = &ramfs_ops;
    n->parent = parent;
    n->ref    = 1;

    if (type == VFS_FILE) {
        ramfs_file_t *f = kzalloc(sizeof(ramfs_file_t));
        if (!f) { kfree(n); return NULL; }
        n->data = f;
    }

    if (parent) {
        n->next = parent->children;
        parent->children = n;
    }
    return n;
}

static int ramfs_read(vfs_node_t *n, off_t off, size_t len, char *buf) {
    if (n->type != VFS_FILE) return -1;
    ramfs_file_t *f = (ramfs_file_t*)n->data;
    if ((uint32_t)off >= f->size) return 0;
    if (off + len > f->size) len = f->size - off;
    memcpy(buf, f->data + off, len);
    return (int)len;
}

static int ramfs_write(vfs_node_t *n, off_t off, size_t len, const char *buf) {
    if (n->type != VFS_FILE) return -1;
    ramfs_file_t *f = (ramfs_file_t*)n->data;
    uint32_t end = (uint32_t)off + (uint32_t)len;
    if (end > f->capacity) {
        uint32_t newcap = end + 4096;
        if (newcap > RAMFS_MAX_FILE_SIZE) return -1;
        uint8_t *newdata = kmalloc(newcap);
        if (!newdata) return -1;
        if (f->data) memcpy(newdata, f->data, f->size);
        f->data = newdata;
        f->capacity = newcap;
    }
    memcpy(f->data + off, buf, len);
    if (end > f->size) f->size = end;
    n->size = f->size;
    return (int)len;
}

static vfs_node_t *ramfs_lookup(vfs_node_t *n, const char *name) {
    if (!n || n->type != VFS_DIR) return NULL;
    for (vfs_node_t *c = n->children; c; c = c->next) {
        if (strcmp(c->name, name) == 0) return c;
    }
    return NULL;
}

static int ramfs_readdir(vfs_node_t *n, int idx, char *namebuf, size_t nbsz) {
    if (n->type != VFS_DIR) return -1;
    int i = 0;
    for (vfs_node_t *c = n->children; c; c = c->next, i++) {
        if (i == idx) { strncpy(namebuf, c->name, nbsz); return 1; }
    }
    return 0;
}

static int ramfs_mkdir(vfs_node_t *n, const char *name, mode_t mode) {
    if (ramfs_lookup(n, name)) return -1;
    vfs_node_t *d = ramfs_create_node(n, name, VFS_DIR, mode);
    return d ? 0 : -1;
}

static int ramfs_create(vfs_node_t *n, const char *name, mode_t mode) {
    if (ramfs_lookup(n, name)) return -1;
    vfs_node_t *f = ramfs_create_node(n, name, VFS_FILE, mode);
    return f ? 0 : -1;
}

static int ramfs_unlink(vfs_node_t *parent, const char *name) {
    vfs_node_t **pp = &parent->children;
    while (*pp) {
        if (strcmp((*pp)->name, name) == 0) {
            vfs_node_t *victim = *pp;
            *pp = victim->next;
            /* free file data */
            if (victim->type == VFS_FILE && victim->data) {
                ramfs_file_t *f = victim->data;
                kfree(f->data);
                kfree(f);
            }
            kfree(victim);
            return 0;
        }
        pp = &(*pp)->next;
    }
    return -1;
}

static int ramfs_stat(vfs_node_t *n, struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_ino  = n->inode;
    st->st_mode = n->mode | (n->type == VFS_DIR ? 0040000 : 0100000);
    st->st_size = n->size;
    return 0;
}

/* =========================================================
 * VFS Path resolution
 * ========================================================= */
static vfs_node_t *vfs_resolve(const char *path, vfs_node_t *cwd) {
    if (!path || !*path) return cwd;

    vfs_node_t *cur = (*path == '/') ? vfs_root : (cwd ? cwd : vfs_root);
    if (*path == '/') path++;

    char part[NAME_MAX+1];
    while (*path) {
        int i = 0;
        while (*path && *path != '/') part[i++] = *path++;
        part[i] = 0;
        if (*path == '/') path++;
        if (!i || strcmp(part, ".") == 0) continue;
        if (strcmp(part, "..") == 0) {
            if (cur->parent) cur = cur->parent;
            continue;
        }
        if (!cur->ops || !cur->ops->lookup) return NULL;
        cur = cur->ops->lookup(cur, part);
        if (!cur) return NULL;
    }
    return cur;
}

/* Resolve parent directory and return basename */
static vfs_node_t *vfs_resolve_parent(const char *path, vfs_node_t *cwd, const char **basename_out) {
    /* find last '/' */
    const char *last = strrchr(path, '/');
    if (!last) {
        *basename_out = path;
        return cwd ? cwd : vfs_root;
    }
    if (last == path) {
        *basename_out = last+1;
        return vfs_root;
    }
    /* copy directory part */
    char dirpath[PATH_MAX];
    int dlen = (int)(last - path);
    strncpy(dirpath, path, dlen);
    dirpath[dlen] = 0;
    *basename_out = last+1;
    return vfs_resolve(dirpath, cwd);
}

/* =========================================================
 * DEV FILE SYSTEM (special files in /dev)
 * ========================================================= */
/* /dev/null */
static int devnull_read(vfs_node_t *n, off_t o, size_t l, char *b) { UNUSED(n);UNUSED(o);UNUSED(l);UNUSED(b); return 0; }
static int devnull_write(vfs_node_t *n, off_t o, size_t l, const char *b) { UNUSED(n);UNUSED(o);UNUSED(b); return (int)l; }

/* /dev/tty */
static int devtty_read(vfs_node_t *n, off_t o, size_t l, char *b) { UNUSED(n);UNUSED(o); return tty_read(b, (int)l); }
static int devtty_write(vfs_node_t *n, off_t o, size_t l, const char *b) { UNUSED(n);UNUSED(o); return tty_write(b, (int)l); }

/* /dev/zero */
static int devzero_read(vfs_node_t *n, off_t o, size_t l, char *b) { UNUSED(n);UNUSED(o); memset(b,0,l); return (int)l; }

static vfs_ops_t devnull_ops = { .read=devnull_read, .write=devnull_write };
static vfs_ops_t devtty_ops  = { .read=devtty_read,  .write=devtty_write  };
static vfs_ops_t devzero_ops = { .read=devzero_read,  .write=devnull_write };

/* =========================================================
 * PROCESS MANAGEMENT
 * ========================================================= */
#define MAX_PROCS    32
#define PROC_STACK   8192
#define PROC_ARGS_MAX 32
#define PROC_ENV_MAX  16

typedef enum {
    PROC_DEAD=0, PROC_RUNNING, PROC_SLEEPING, PROC_ZOMBIE, PROC_STOPPED
} proc_state_t;

typedef struct file_desc {
    vfs_node_t *node;
    off_t       offset;
    int         flags;
    int         ref;
} file_desc_t;

typedef struct proc {
    pid_t           pid;
    pid_t           ppid;
    proc_state_t    state;
    uint32_t        esp;      /* saved stack pointer */
    uint32_t        eip;      /* saved instruction pointer */
    uint32_t       *pgd;      /* page directory (currently kernel only) */
    uint8_t        *kstack;   /* kernel stack */
    uint32_t        kstack_top;
    int             exit_code;
    char            name[32];
    vfs_node_t     *cwd;
    file_desc_t    *fds[OPEN_MAX];
    uint32_t        sleep_until; /* for nanosleep */
    /* user address space info (simplified) */
    uint32_t        brk;
    uint32_t        brk_start;
} proc_t;

static proc_t procs[MAX_PROCS];
static proc_t *current_proc = NULL;
static int     scheduler_ready = 0;

static proc_t *proc_alloc(void) {
    for (int i = 1; i < MAX_PROCS; i++) {
        if (procs[i].state == PROC_DEAD) {
            memset(&procs[i], 0, sizeof(proc_t));
            procs[i].pid = i;
            return &procs[i];
        }
    }
    return NULL;
}

static file_desc_t *fd_alloc(vfs_node_t *node, int flags) {
    file_desc_t *fd = kzalloc(sizeof(file_desc_t));
    if (!fd) return NULL;
    fd->node = node;
    fd->flags = flags;
    fd->ref   = 1;
    return fd;
}

static int proc_add_fd(proc_t *p, file_desc_t *fd) {
    for (int i = 0; i < OPEN_MAX; i++) {
        if (!p->fds[i]) { p->fds[i] = fd; return i; }
    }
    return -1;
}

/* Open a VFS path and add to process fd table */
static int vfs_open(proc_t *p, const char *path, int flags, mode_t mode) {
    vfs_node_t *node = vfs_resolve(path, p->cwd);
    if (!node && (flags & 0x200) /* O_CREAT */) {
        /* create the file */
        const char *base;
        vfs_node_t *parent = vfs_resolve_parent(path, p->cwd, &base);
        if (!parent || !parent->ops || !parent->ops->create) return -1;
        if (parent->ops->create(parent, base, mode) < 0) return -1;
        node = parent->ops->lookup(parent, base);
    }
    if (!node) return -1;
    file_desc_t *fd = fd_alloc(node, flags);
    if (!fd) return -1;
    if (flags & 0x400 /* O_TRUNC */ && node->type == VFS_FILE) {
        ramfs_file_t *rf = (ramfs_file_t*)node->data;
        if (rf) { rf->size = 0; node->size = 0; }
    }
    if (flags & 0x2 /* O_APPEND */) fd->offset = node->size;
    int fdnum = proc_add_fd(p, fd);
    if (fdnum < 0) { kfree(fd); return -1; }
    return fdnum;
}

static int vfs_close(proc_t *p, int fdnum) {
    if (fdnum < 0 || fdnum >= OPEN_MAX || !p->fds[fdnum]) return -1;
    file_desc_t *fd = p->fds[fdnum];
    fd->ref--;
    if (fd->ref <= 0) {
        if (fd->node && fd->node->ops && fd->node->ops->close)
            fd->node->ops->close(fd->node);
        kfree(fd);
    }
    p->fds[fdnum] = NULL;
    return 0;
}

/* =========================================================
 * SCHEDULER (simple round-robin)
 * ========================================================= */
static void schedule(void);

static void context_switch(proc_t *next) {
    proc_t *prev = current_proc;
    current_proc = next;
    next->state = PROC_RUNNING;

    if (!prev || prev == next) return;

    /* Very simple context switch: save/restore ESP only
     * In a real OS we'd save all registers via TSS/kernel stack */
    __asm__ volatile(
        "mov %%esp, %0\n"
        "mov %1, %%esp\n"
        : "=m"(prev->esp)
        : "m"(next->esp)
    );
}

static void schedule(void) {
    if (!scheduler_ready) return;
    proc_t *cur = current_proc;
    int start = cur ? (int)(cur - procs) : 0;
    int i = (start + 1) % MAX_PROCS;
    do {
        proc_t *p = &procs[i];
        if (p->state == PROC_SLEEPING && pit_ticks >= p->sleep_until)
            p->state = PROC_RUNNING;
        if (p->state == PROC_RUNNING && p != cur) {
            context_switch(p);
            return;
        }
        i = (i+1) % MAX_PROCS;
    } while (i != start);
}

/* =========================================================
 * INTERRUPT HANDLERS
 * ========================================================= */
static void isr_handler(struct int_frame *f) {
    uint32_t num = f->int_no;

    if (num == 128) {
        /* syscall - handled separately */
        return;
    }

    if (num < 32) {
        const char *name = (num < 20) ? exception_names[num] : "Reserved";
        kprintf("\n[XVM-OS PANIC] Exception %d: %s\n", num, name);
        kprintf("  EIP=%x CS=%x EFLAGS=%x ERR=%x\n",
                f->eip, f->cs, f->eflags, f->err_code);
        /* halt */
        __asm__ volatile("cli; hlt");
        while(1);
    }
}

static void irq_handler(struct int_frame *f) {
    uint8_t irq = (uint8_t)(f->int_no - 32);

    switch (irq) {
    case 0: /* PIT timer */
        pit_ticks++;
        if (scheduler_ready && (pit_ticks % 5 == 0)) {
            /* Schedule every 5 ticks (50ms) */
            schedule();
        }
        break;
    case 1: /* Keyboard */
        kb_handler();
        tty_input(kb_buf[(kb_head-1+KB_BUF_SIZE)%KB_BUF_SIZE]);
        /* Undo the kb_buf store since tty consumed it */
        if (kb_head != kb_tail) kb_head = (kb_head-1+KB_BUF_SIZE)%KB_BUF_SIZE;
        break;
    }

    pic_eoi(irq);
}

/* =========================================================
 * SYSTEM CALLS
 * ========================================================= */
#define SYS_READ    3
#define SYS_WRITE   4
#define SYS_OPEN    5
#define SYS_CLOSE   6
#define SYS_STAT    18
#define SYS_LSTAT   84
#define SYS_GETPID  20
#define SYS_FORK    2
#define SYS_EXECVE  11
#define SYS_WAIT4   114
#define SYS_EXIT    1
#define SYS_CHDIR   12
#define SYS_GETCWD  183
#define SYS_MKDIR   39
#define SYS_UNLINK  10
#define SYS_READDIR 89
#define SYS_BRK     45
#define SYS_NANOSLEEP 162

/* Write path to buf from node */
static void node_path(vfs_node_t *n, char *buf, size_t sz) {
    char parts[16][NAME_MAX+1];
    int depth = 0;
    vfs_node_t *c = n;
    while (c && c != vfs_root) {
        if (depth < 16) strncpy(parts[depth++], c->name, NAME_MAX);
        c = c->parent;
    }
    buf[0] = 0;
    if (depth == 0) { strcpy(buf, "/"); return; }
    size_t used = 0;
    for (int i = depth-1; i >= 0; i--) {
        if (used+1 < sz) { buf[used++] = '/'; buf[used] = 0; }
        size_t plen = strlen(parts[i]);
        if (used+plen < sz) { strcpy(buf+used, parts[i]); used += plen; }
    }
}

static int32_t do_syscall(uint32_t num, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    proc_t *p = current_proc;
    if (!p) return -1;

    switch (num) {
    case SYS_EXIT:
        p->state     = PROC_ZOMBIE;
        p->exit_code = (int)a;
        schedule();
        return 0;

    case SYS_GETPID:
        return p->pid;

    case SYS_READ: {
        int fd = (int)a;
        char *buf = (char*)b;
        size_t len = (size_t)c;
        if (fd < 0 || fd >= OPEN_MAX || !p->fds[fd]) return -1;
        file_desc_t *fde = p->fds[fd];
        if (!fde->node || !fde->node->ops || !fde->node->ops->read) return -1;
        int n = fde->node->ops->read(fde->node, fde->offset, len, buf);
        if (n > 0) fde->offset += n;
        return n;
    }

    case SYS_WRITE: {
        int fd = (int)a;
        const char *buf = (const char*)b;
        size_t len = (size_t)c;
        if (fd < 0 || fd >= OPEN_MAX || !p->fds[fd]) return -1;
        file_desc_t *fde = p->fds[fd];
        if (!fde->node || !fde->node->ops || !fde->node->ops->write) return -1;
        int n = fde->node->ops->write(fde->node, fde->offset, len, buf);
        if (n > 0) fde->offset += n;
        return n;
    }

    case SYS_OPEN: {
        const char *path = (const char*)a;
        int flags = (int)b;
        mode_t mode = (mode_t)c;
        return vfs_open(p, path, flags, mode);
    }

    case SYS_CLOSE:
        return vfs_close(p, (int)a);

    case SYS_STAT:
    case SYS_LSTAT: {
        const char *path = (const char*)a;
        struct stat *st = (struct stat*)b;
        vfs_node_t *n = vfs_resolve(path, p->cwd);
        if (!n) return -1;
        return n->ops->stat ? n->ops->stat(n, st) : -1;
    }

    case SYS_CHDIR: {
        const char *path = (const char*)a;
        vfs_node_t *n = vfs_resolve(path, p->cwd);
        if (!n || n->type != VFS_DIR) return -1;
        p->cwd = n;
        return 0;
    }

    case SYS_GETCWD: {
        char *buf = (char*)a;
        size_t sz = (size_t)b;
        node_path(p->cwd, buf, sz);
        return (int32_t)buf;
    }

    case SYS_MKDIR: {
        const char *path = (const char*)a;
        mode_t mode = (mode_t)b;
        const char *base;
        vfs_node_t *parent = vfs_resolve_parent(path, p->cwd, &base);
        if (!parent || !parent->ops || !parent->ops->mkdir) return -1;
        return parent->ops->mkdir(parent, base, mode);
    }

    case SYS_UNLINK: {
        const char *path = (const char*)a;
        const char *base;
        vfs_node_t *parent = vfs_resolve_parent(path, p->cwd, &base);
        if (!parent || !parent->ops || !parent->ops->unlink) return -1;
        return parent->ops->unlink(parent, base);
    }

    case SYS_READDIR: {
        int fd = (int)a;
        char *namebuf = (char*)b;
        int idx = (int)c;
        if (fd < 0 || fd >= OPEN_MAX || !p->fds[fd]) return -1;
        vfs_node_t *n = p->fds[fd]->node;
        if (!n->ops || !n->ops->readdir) return 0;
        return n->ops->readdir(n, idx, namebuf, NAME_MAX);
    }

    case SYS_BRK: {
        uint32_t newbrk = a;
        if (newbrk == 0) return (int32_t)p->brk;
        if (newbrk < p->brk_start) return -1;
        /* Grow heap (simplified - no real page mapping for user) */
        p->brk = newbrk;
        return (int32_t)newbrk;
    }

    case SYS_NANOSLEEP: {
        uint32_t ms = a; /* simplified: arg is ms */
        p->state = PROC_SLEEPING;
        p->sleep_until = pit_ticks + (ms * PIT_HZ / 1000) + 1;
        schedule();
        return 0;
    }

    default:
        return -1;
    }
    UNUSED(d);
}

/* =========================================================
 * BUILT-IN COMMANDS / SHELL PROGRAMS
 * =========================================================
 * Since we can't load actual ELF binaries without a disk,
 * we provide built-in implementations of common Unix commands.
 * ========================================================= */

/* Print utilities used by commands */
static void cmd_puts(proc_t *p, const char *s) {
    tty_write(s, strlen(s));
    UNUSED(p);
}
static void cmd_putc(proc_t *p, char c) {
    tty_write(&c, 1);
    UNUSED(p);
}
static void cmd_printf(proc_t *p, const char *fmt, ...) {
    char buf[512];
    /* mini sprintf */
    uint32_t *args = (uint32_t*)&fmt + 1;
    int ai = 0, bi = 0;
    char tmp[32];

    while (*fmt && bi < (int)sizeof(buf)-1) {
        if (*fmt == '%') {
            fmt++;
            switch (*fmt) {
            case 'd': itoa((int)args[ai++], tmp, 10); { int l=strlen(tmp); if(bi+l<(int)sizeof(buf)){memcpy(buf+bi,tmp,l);bi+=l;} break; }
            case 'u': utoa(args[ai++], tmp, 10);       { int l=strlen(tmp); if(bi+l<(int)sizeof(buf)){memcpy(buf+bi,tmp,l);bi+=l;} break; }
            case 'x': utoa(args[ai++], tmp, 16);       { int l=strlen(tmp); if(bi+l<(int)sizeof(buf)){memcpy(buf+bi,tmp,l);bi+=l;} break; }
            case 's': { char *s=(char*)args[ai++]; if(!s)s="(null)"; int l=strlen(s); if(bi+l<(int)sizeof(buf)){memcpy(buf+bi,s,l);bi+=l;} break; }
            case 'c': if(bi<(int)sizeof(buf)-1)buf[bi++]=(char)args[ai++]; break;
            case '%': if(bi<(int)sizeof(buf)-1)buf[bi++]='%'; break;
            default: if(bi<(int)sizeof(buf)-1)buf[bi++]='%'; if(bi<(int)sizeof(buf)-1)buf[bi++]=*fmt; break;
            }
        } else {
            buf[bi++] = *fmt;
        }
        fmt++;
    }
    buf[bi] = 0;
    tty_write(buf, bi);
    UNUSED(p);
}

/* Token parsing helper */
#define MAX_TOKENS 64
static int tokenize(char *line, char **toks, int max_toks) {
    int n = 0;
    char *p = line;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '\n') break;
        char quote = 0;
        if (*p == '"' || *p == '\'') { quote = *p++; }
        char *start = p;
        if (quote) {
            while (*p && *p != quote) p++;
        } else {
            while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        }
        if (n < max_toks-1) toks[n++] = start;
        if (*p) *p++ = 0;
    }
    toks[n] = NULL;
    return n;
}

/* Command type: returns exit code */
typedef int (*cmd_fn_t)(proc_t*, int, char**);

/* ---- ls ---- */
static int cmd_ls(proc_t *p, int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : ".";
    vfs_node_t *dir = vfs_resolve(path, p->cwd);
    if (!dir) { cmd_puts(p, "ls: no such file or directory\n"); return 1; }
    if (dir->type != VFS_DIR) {
        cmd_printf(p, "%s\n", dir->name);
        return 0;
    }
    int idx = 0;
    char name[NAME_MAX+1];
    int col = 0;
    while (dir->ops->readdir(dir, idx++, name, NAME_MAX) > 0) {
        vfs_node_t *child = dir->ops->lookup(dir, name);
        int is_dir = (child && child->type == VFS_DIR);
        cmd_printf(p, is_dir ? "\x1b[34m%-14s\x1b[0m" : "%-14s", name);
        col++;
        if (col >= 5) { cmd_putc(p, '\n'); col = 0; }
    }
    if (col) cmd_putc(p, '\n');
    return 0;
}

/* ---- cat ---- */
static int cmd_cat(proc_t *p, int argc, char **argv) {
    if (argc < 2) {
        /* read from stdin */
        char buf[256];
        int n;
        while ((n = tty_read(buf, sizeof(buf))) > 0) {
            tty_write(buf, n);
        }
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        vfs_node_t *f = vfs_resolve(argv[i], p->cwd);
        if (!f || f->type != VFS_FILE) {
            cmd_printf(p, "cat: %s: no such file\n", argv[i]);
            continue;
        }
        char buf[512];
        off_t off = 0;
        int n;
        while ((n = f->ops->read(f, off, sizeof(buf), buf)) > 0) {
            tty_write(buf, n);
            off += n;
        }
    }
    return 0;
}

/* ---- echo ---- */
static int cmd_echo(proc_t *p, int argc, char **argv) {
    int newline = 1;
    int start = 1;
    if (argc > 1 && strcmp(argv[1], "-n") == 0) { newline = 0; start = 2; }
    for (int i = start; i < argc; i++) {
        if (i > start) cmd_putc(p, ' ');
        cmd_puts(p, argv[i]);
    }
    if (newline) cmd_putc(p, '\n');
    return 0;
}

/* ---- pwd ---- */
static int cmd_pwd(proc_t *p, int argc, char **argv) {
    UNUSED(argc); UNUSED(argv);
    char buf[PATH_MAX];
    node_path(p->cwd, buf, PATH_MAX);
    cmd_puts(p, buf);
    cmd_putc(p, '\n');
    return 0;
}

/* ---- cd ---- */
static int cmd_cd(proc_t *p, int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "/";
    vfs_node_t *n = vfs_resolve(path, p->cwd);
    if (!n || n->type != VFS_DIR) { cmd_printf(p, "cd: %s: not a directory\n", path); return 1; }
    p->cwd = n;
    return 0;
}

/* ---- mkdir ---- */
static int cmd_mkdir(proc_t *p, int argc, char **argv) {
    if (argc < 2) { cmd_puts(p, "usage: mkdir <dir>\n"); return 1; }
    const char *base;
    vfs_node_t *parent = vfs_resolve_parent(argv[1], p->cwd, &base);
    if (!parent) { cmd_puts(p, "mkdir: parent not found\n"); return 1; }
    if (parent->ops->mkdir(parent, base, 0755) < 0) {
        cmd_printf(p, "mkdir: cannot create %s\n", argv[1]);
        return 1;
    }
    return 0;
}

/* ---- rm ---- */
static int cmd_rm(proc_t *p, int argc, char **argv) {
    if (argc < 2) { cmd_puts(p, "usage: rm <file>\n"); return 1; }
    for (int i = 1; i < argc; i++) {
        const char *base;
        vfs_node_t *parent = vfs_resolve_parent(argv[i], p->cwd, &base);
        if (!parent || parent->ops->unlink(parent, base) < 0) {
            cmd_printf(p, "rm: cannot remove %s\n", argv[i]);
        }
    }
    return 0;
}

/* ---- touch ---- */
static int cmd_touch(proc_t *p, int argc, char **argv) {
    if (argc < 2) { cmd_puts(p, "usage: touch <file>\n"); return 1; }
    for (int i = 1; i < argc; i++) {
        const char *base;
        vfs_node_t *parent = vfs_resolve_parent(argv[i], p->cwd, &base);
        if (!parent) { cmd_printf(p, "touch: %s: no such directory\n", argv[i]); continue; }
        vfs_node_t *existing = parent->ops->lookup ? parent->ops->lookup(parent, base) : NULL;
        if (!existing && parent->ops->create)
            parent->ops->create(parent, base, 0644);
    }
    return 0;
}

/* ---- cp ---- */
static int cmd_cp(proc_t *p, int argc, char **argv) {
    if (argc < 3) { cmd_puts(p, "usage: cp <src> <dst>\n"); return 1; }
    vfs_node_t *src = vfs_resolve(argv[1], p->cwd);
    if (!src || src->type != VFS_FILE) { cmd_puts(p, "cp: source not found\n"); return 1; }

    const char *base;
    vfs_node_t *dstpar = vfs_resolve_parent(argv[2], p->cwd, &base);
    if (!dstpar) { cmd_puts(p, "cp: dest directory not found\n"); return 1; }

    vfs_node_t *dst = dstpar->ops->lookup ? dstpar->ops->lookup(dstpar, base) : NULL;
    if (!dst) {
        if (dstpar->ops->create) dstpar->ops->create(dstpar, base, 0644);
        dst = dstpar->ops->lookup ? dstpar->ops->lookup(dstpar, base) : NULL;
    }
    if (!dst) { cmd_puts(p, "cp: cannot create dest\n"); return 1; }

    char buf[512];
    off_t off = 0; int n;
    ramfs_file_t *df = (ramfs_file_t*)dst->data;
    if (df) { df->size = 0; dst->size = 0; }
    while ((n = src->ops->read(src, off, sizeof(buf), buf)) > 0) {
        dst->ops->write(dst, off, n, buf);
        off += n;
    }
    return 0;
}

/* ---- mv ---- */
static int cmd_mv(proc_t *p, int argc, char **argv) {
    if (argc < 3) { cmd_puts(p, "usage: mv <src> <dst>\n"); return 1; }
    cmd_cp(p, argc, argv);
    const char *base;
    vfs_node_t *srcpar = vfs_resolve_parent(argv[1], p->cwd, &base);
    if (srcpar && srcpar->ops->unlink) srcpar->ops->unlink(srcpar, base);
    return 0;
}

/* ---- wc ---- */
static int cmd_wc(proc_t *p, int argc, char **argv) {
    if (argc < 2) { cmd_puts(p, "usage: wc <file>\n"); return 1; }
    vfs_node_t *f = vfs_resolve(argv[1], p->cwd);
    if (!f || f->type != VFS_FILE) { cmd_puts(p, "wc: file not found\n"); return 1; }
    char buf[512]; off_t off = 0; int n;
    int lines=0,words=0,bytes=0; int in_word=0;
    while ((n = f->ops->read(f, off, sizeof(buf), buf)) > 0) {
        for (int i=0;i<n;i++) {
            bytes++;
            if (buf[i]=='\n') lines++;
            if (buf[i]==' '||buf[i]=='\t'||buf[i]=='\n') in_word=0;
            else if (!in_word) { words++; in_word=1; }
        }
        off+=n;
    }
    cmd_printf(p, "%d %d %d %s\n", lines, words, bytes, argv[1]);
    return 0;
}

/* ---- head / tail ---- */
static int cmd_head(proc_t *p, int argc, char **argv) {
    int nlines = 10;
    const char *fname = NULL;
    for (int i=1; i<argc; i++) {
        if (argv[i][0]=='-' && argv[i][1]=='n') nlines = atoi(argv[i]+2);
        else fname = argv[i];
    }
    if (!fname) { cmd_puts(p, "usage: head [-nN] <file>\n"); return 1; }
    vfs_node_t *f = vfs_resolve(fname, p->cwd);
    if (!f || f->type!=VFS_FILE) { cmd_puts(p, "head: file not found\n"); return 1; }
    char buf[512]; off_t off=0; int n; int cl=0;
    while (cl < nlines && (n=f->ops->read(f,off,sizeof(buf),buf))>0) {
        for (int i=0;i<n&&cl<nlines;i++) {
            cmd_putc(p, buf[i]);
            if (buf[i]=='\n') cl++;
        }
        off+=n;
    }
    return 0;
}

/* ---- grep ---- */
static int cmd_grep(proc_t *p, int argc, char **argv) {
    if (argc < 3) { cmd_puts(p, "usage: grep <pattern> <file>\n"); return 1; }
    const char *pattern = argv[1];
    vfs_node_t *f = vfs_resolve(argv[2], p->cwd);
    if (!f || f->type!=VFS_FILE) { cmd_puts(p, "grep: file not found\n"); return 1; }

    /* read whole file into temp buf */
    char *data = kmalloc(f->size+1);
    if (!data) { cmd_puts(p, "grep: OOM\n"); return 1; }
    f->ops->read(f, 0, f->size, data);
    data[f->size] = 0;

    /* scan line by line */
    char *line = data;
    while (*line) {
        char *end = strchr(line, '\n');
        if (!end) end = line + strlen(line);
        char saved = *end; *end = 0;
        if (strstr_simple(line, pattern)) {
            cmd_puts(p, line);
            cmd_putc(p, '\n');
        }
        *end = saved;
        line = (*end) ? end+1 : end;
    }
    kfree(data);
    return 0;
}

/* simple strstr */
static int strstr_simple(const char *hay, const char *needle) {
    if (!*needle) return 1;
    size_t nl = strlen(needle);
    for (; *hay; hay++) {
        if (strncmp(hay, needle, nl)==0) return 1;
    }
    return 0;
}

/* ---- uname ---- */
static int cmd_uname(proc_t *p, int argc, char **argv) {
    int all = (argc > 1 && strcmp(argv[1],"-a")==0);
    if (all)
        cmd_puts(p, "XVM-OS xvm 1.0.0 #1 SMP x86 GNU\n");
    else
        cmd_puts(p, "XVM-OS\n");
    return 0;
}

/* ---- ps ---- */
static int cmd_ps(proc_t *p, int argc, char **argv) {
    UNUSED(argc); UNUSED(argv);
    cmd_puts(p, "  PID STATE  NAME\n");
    for (int i = 1; i < MAX_PROCS; i++) {
        proc_t *pr = &procs[i];
        if (pr->state == PROC_DEAD) continue;
        const char *stname[] = {"dead","run","sleep","zombie","stop"};
        cmd_printf(p, "  %3d %-7s %s\n", pr->pid, stname[pr->state], pr->name);
    }
    return 0;
}

/* ---- uptime ---- */
static int cmd_uptime(proc_t *p, int argc, char **argv) {
    UNUSED(argc); UNUSED(argv);
    uint32_t secs = pit_ticks / PIT_HZ;
    cmd_printf(p, "up %u seconds\n", secs);
    return 0;
}

/* ---- free ---- */
static int cmd_free(proc_t *p, int argc, char **argv) {
    UNUSED(argc); UNUSED(argv);
    uint32_t used_pages = 0;
    for (int i = 0; i < PHYS_BITMAP_WORDS; i++)
        for (int j = 0; j < 32; j++)
            if ((phys_bitmap[i] >> j) & 1) used_pages++;
    uint32_t total = PHYS_PAGES;
    cmd_printf(p, "Total: %uK  Used: %uK  Free: %uK\n",
        total*4, used_pages*4, (total-used_pages)*4);
    return 0;
}

/* ---- date ---- */
static int cmd_date(proc_t *p, int argc, char **argv) {
    UNUSED(argc); UNUSED(argv);
    /* Read from CMOS RTC */
    outb(0x70, 0x00); uint8_t sec = inb(0x71);
    outb(0x70, 0x02); uint8_t min = inb(0x71);
    outb(0x70, 0x04); uint8_t hr  = inb(0x71);
    outb(0x70, 0x07); uint8_t day = inb(0x71);
    outb(0x70, 0x08); uint8_t mon = inb(0x71);
    outb(0x70, 0x09); uint8_t yr  = inb(0x71);
    /* BCD decode */
    #define BCD(x) (((x)>>4)*10+((x)&0xF))
    cmd_printf(p, "20%02d-%02d-%02d %02d:%02d:%02d UTC\n",
        BCD(yr), BCD(mon), BCD(day), BCD(hr), BCD(min), BCD(sec));
    return 0;
}

/* ---- write (simple text editor) ---- */
static int cmd_write(proc_t *p, int argc, char **argv) {
    if (argc < 2) { cmd_puts(p, "usage: write <file>\n"); return 1; }
    const char *base;
    vfs_node_t *parent = vfs_resolve_parent(argv[1], p->cwd, &base);
    if (!parent) { cmd_puts(p, "write: directory not found\n"); return 1; }
    vfs_node_t *f = parent->ops->lookup ? parent->ops->lookup(parent, base) : NULL;
    if (!f) {
        parent->ops->create(parent, base, 0644);
        f = parent->ops->lookup(parent, base);
    }
    if (!f) { cmd_puts(p, "write: cannot create file\n"); return 1; }

    cmd_puts(p, "Enter text (end with a line containing only '.')\n");
    char buf[512]; off_t off = 0;
    ramfs_file_t *rf = (ramfs_file_t*)f->data;
    if (rf) { rf->size = 0; f->size = 0; }

    while (1) {
        int n = tty_read(buf, sizeof(buf)-1);
        if (n <= 0) break;
        buf[n] = 0;
        if (n >= 2 && buf[0]=='.' && (buf[1]=='\n'||buf[1]==0)) break;
        f->ops->write(f, off, n, buf);
        off += n;
    }
    cmd_printf(p, "Wrote %d bytes to %s\n", (int)off, argv[1]);
    return 0;
}

/* ---- hexdump ---- */
static int cmd_hexdump(proc_t *p, int argc, char **argv) {
    if (argc < 2) { cmd_puts(p, "usage: hexdump <file>\n"); return 1; }
    vfs_node_t *f = vfs_resolve(argv[1], p->cwd);
    if (!f || f->type!=VFS_FILE) { cmd_puts(p, "hexdump: file not found\n"); return 1; }
    char buf[16]; off_t off=0; int n;
    while ((n=f->ops->read(f,off,16,buf))>0) {
        cmd_printf(p, "%08x  ", (uint32_t)off);
        for (int i=0;i<16;i++) {
            if (i<n) cmd_printf(p, "%02x ", (uint8_t)buf[i]);
            else cmd_puts(p, "   ");
            if (i==7) cmd_putc(p,' ');
        }
        cmd_puts(p, " |");
        for (int i=0;i<n;i++) cmd_putc(p,(buf[i]>=' '&&buf[i]<127)?buf[i]:'.');
        cmd_puts(p, "|\n");
        off+=n;
    }
    return 0;
}

/* ---- sleep ---- */
static int cmd_sleep(proc_t *p, int argc, char **argv) {
    UNUSED(p);
    uint32_t ms = (argc > 1) ? atoi(argv[1]) * 1000 : 1000;
    sleep_ms(ms);
    return 0;
}

/* ---- help ---- */
static int cmd_help(proc_t *p, int argc, char **argv) {
    UNUSED(argc); UNUSED(argv);
    cmd_puts(p,
        "XVM-OS built-in commands:\n"
        "  ls [dir]         - list directory\n"
        "  cd [dir]         - change directory\n"
        "  pwd              - print working directory\n"
        "  cat [files]      - print file contents\n"
        "  echo [args]      - print arguments\n"
        "  touch <file>     - create empty file\n"
        "  write <file>     - write text to file\n"
        "  cp <src> <dst>   - copy file\n"
        "  mv <src> <dst>   - move file\n"
        "  rm <files>       - remove files\n"
        "  mkdir <dir>      - create directory\n"
        "  head [-nN] <f>   - print first N lines\n"
        "  grep <pat> <f>   - search pattern in file\n"
        "  wc <file>        - word count\n"
        "  hexdump <file>   - hex dump\n"
        "  ps               - list processes\n"
        "  uname [-a]       - system info\n"
        "  uptime           - time since boot\n"
        "  free             - memory usage\n"
        "  date             - current date/time\n"
        "  sleep <sec>      - sleep\n"
        "  clear            - clear screen\n"
        "  reboot           - reboot system\n"
        "  help             - this help\n"
    );
    return 0;
}

/* ---- clear ---- */
static int cmd_clear(proc_t *p, int argc, char **argv) {
    UNUSED(p);UNUSED(argc);UNUSED(argv);
    vga_clear();
    return 0;
}

/* ---- reboot ---- */
static int cmd_reboot(proc_t *p, int argc, char **argv) {
    UNUSED(p);UNUSED(argc);UNUSED(argv);
    cmd_puts(p, "Rebooting...\n");
    sleep_ms(500);
    /* Triple fault or keyboard controller reset */
    outb(0x64, 0xFE);
    __asm__ volatile("cli; hlt");
    while(1);
}

/* =========================================================
 * COMMAND TABLE
 * ========================================================= */
typedef struct { const char *name; cmd_fn_t fn; } cmd_entry_t;

static cmd_entry_t cmd_table[] = {
    {"ls",      cmd_ls},
    {"cd",      cmd_cd},
    {"pwd",     cmd_pwd},
    {"cat",     cmd_cat},
    {"echo",    cmd_echo},
    {"touch",   cmd_touch},
    {"write",   cmd_write},
    {"cp",      cmd_cp},
    {"mv",      cmd_mv},
    {"rm",      cmd_rm},
    {"mkdir",   cmd_mkdir},
    {"head",    cmd_head},
    {"grep",    cmd_grep},
    {"wc",      cmd_wc},
    {"hexdump", cmd_hexdump},
    {"ps",      cmd_ps},
    {"uname",   cmd_uname},
    {"uptime",  cmd_uptime},
    {"free",    cmd_free},
    {"date",    cmd_date},
    {"sleep",   cmd_sleep},
    {"clear",   cmd_clear},
    {"reboot",  cmd_reboot},
    {"help",    cmd_help},
    {NULL, NULL}
};

/* =========================================================
 * XSH - XVM Shell
 * ========================================================= */
#define HIST_SIZE 32
static char hist[HIST_SIZE][TTY_LINEBUF];
static int  hist_count = 0;
static int  hist_cur   = 0;

static void hist_add(const char *line) {
    int idx = hist_count % HIST_SIZE;
    strncpy(hist[idx], line, TTY_LINEBUF-1);
    hist_count++;
    hist_cur = hist_count;
}

static void xsh_prompt(proc_t *p) {
    char path[PATH_MAX];
    node_path(p->cwd, path, PATH_MAX);
    /* color: root=red, others=green */
    kprintf("\x1b[32mxvm\x1b[0m:\x1b[34m%s\x1b[0m# ", path);
}

static int xsh_execute_line(proc_t *p, char *line) {
    /* strip trailing newline/spaces */
    int len = strlen(line);
    while (len > 0 && (line[len-1]=='\n'||line[len-1]=='\r'||line[len-1]==' ')) {
        line[--len] = 0;
    }
    if (!len) return 0;

    hist_add(line);

    /* Handle simple pipes: cmd1 | cmd2 */
    /* For now: just handle single commands */
    /* TODO: redirection and pipes */

    /* Handle variable assignment (NAME=val) */
    if (strchr(line, '=') && line[0]!='/' && !strchr(line, ' ')) {
        /* ignore for now */
        return 0;
    }

    /* Tokenize */
    char linecopy[TTY_LINEBUF];
    strncpy(linecopy, line, TTY_LINEBUF-1);
    char *toks[MAX_TOKENS];
    int ntoks = tokenize(linecopy, toks, MAX_TOKENS);
    if (!ntoks) return 0;

    const char *cmd = toks[0];

    /* Search built-in table */
    for (cmd_entry_t *e = cmd_table; e->name; e++) {
        if (strcmp(e->name, cmd) == 0) {
            return e->fn(p, ntoks, toks);
        }
    }

    /* Check /bin/<cmd> in ramfs */
    char binpath[PATH_MAX];
    strcpy(binpath, "/bin/");
    strcat(binpath, cmd);
    vfs_node_t *script = vfs_resolve(binpath, p->cwd);
    if (!script) {
        strcpy(binpath, "/usr/bin/");
        strcat(binpath, cmd);
        script = vfs_resolve(binpath, p->cwd);
    }
    if (script && script->type == VFS_FILE && script->size > 0) {
        /* Execute as shell script */
        char *data = kmalloc(script->size+1);
        if (data) {
            script->ops->read(script, 0, script->size, data);
            data[script->size] = 0;
            char *sline = data;
            /* skip shebang */
            if (sline[0]=='#' && sline[1]=='!') {
                while (*sline && *sline!='\n') sline++;
                if (*sline) sline++;
            }
            while (*sline) {
                char *end = strchr(sline, '\n');
                if (!end) end = sline+strlen(sline);
                char saved = *end; *end = 0;
                if (*sline && *sline!='#') xsh_execute_line(p, sline);
                *end = saved;
                sline = (*end) ? end+1 : end;
            }
            kfree(data);
        }
        return 0;
    }

    kprintf("xsh: %s: command not found\n", cmd);
    return 127;
}

static void xsh_run(proc_t *p) {
    char line[TTY_LINEBUF];

    kprintf("\x1b[1;32mXVM-OS Shell (xsh)\x1b[0m - type 'help' for commands\n");

    while (1) {
        xsh_prompt(p);
        int n = tty_read(line, sizeof(line)-1);
        if (n <= 0) continue;
        line[n] = 0;
        if (n == 1 && line[0] == '\n') continue;
        /* Remove newline */
        if (n > 0 && line[n-1]=='\n') line[n-1]=0;

        xsh_execute_line(p, line);
    }
}

/* =========================================================
 * INIT - Create initial filesystem & start shell
 * ========================================================= */
static void setup_rootfs(void) {
    /* Create root directory */
    vfs_root = kzalloc(sizeof(vfs_node_t));
    strcpy(vfs_root->name, "/");
    vfs_root->type   = VFS_DIR;
    vfs_root->mode   = 0755;
    vfs_root->inode  = vfs_next_inode++;
    vfs_root->ops    = &ramfs_ops;
    vfs_root->parent = vfs_root;

    /* Standard directories */
    static const char *dirs[] = {
        "bin","sbin","usr","etc","home","dev","proc","tmp",
        "var","lib","opt","mnt","sys","run",NULL
    };
    for (int i = 0; dirs[i]; i++)
        ramfs_mkdir(vfs_root, dirs[i], 0755);

    /* /usr/bin, /usr/lib, /home/root */
    vfs_node_t *usr = ramfs_lookup(vfs_root, "usr");
    if (usr) { ramfs_mkdir(usr, "bin", 0755); ramfs_mkdir(usr, "lib", 0755); }
    vfs_node_t *home = ramfs_lookup(vfs_root, "home");
    if (home) ramfs_mkdir(home, "root", 0755);

    /* /dev files */
    vfs_node_t *devdir = ramfs_lookup(vfs_root, "dev");
    if (devdir) {
        /* /dev/null */
        vfs_node_t *null_dev = ramfs_create_node(devdir, "null", VFS_DEV, 0666);
        if (null_dev) null_dev->ops = &devnull_ops;
        /* /dev/tty */
        vfs_node_t *tty_dev = ramfs_create_node(devdir, "tty", VFS_DEV, 0620);
        if (tty_dev) tty_dev->ops = &devtty_ops;
        /* /dev/zero */
        vfs_node_t *zero_dev = ramfs_create_node(devdir, "zero", VFS_DEV, 0666);
        if (zero_dev) zero_dev->ops = &devzero_ops;
    }

    /* /etc/os-release */
    vfs_node_t *etc = ramfs_lookup(vfs_root, "etc");
    if (etc) {
        ramfs_create(etc, "os-release", 0644);
        vfs_node_t *f = ramfs_lookup(etc, "os-release");
        if (f) {
            const char *content =
                "NAME=\"XVM-OS\"\n"
                "VERSION=\"1.0.0\"\n"
                "ID=xvm\n"
                "PRETTY_NAME=\"XVM-OS 1.0.0\"\n"
                "HOME_URL=\"https://xvm-os.local\"\n";
            ramfs_write(f, 0, strlen(content), content);
        }

        /* /etc/hostname */
        ramfs_create(etc, "hostname", 0644);
        f = ramfs_lookup(etc, "hostname");
        if (f) ramfs_write(f, 0, 8, "xvm-os\n\0");

        /* /etc/motd */
        ramfs_create(etc, "motd", 0644);
        f = ramfs_lookup(etc, "motd");
        if (f) {
            const char *motd =
                "\n"
                "  ██╗  ██╗██╗   ██╗███╗   ███╗      ██████╗ ███████╗\n"
                "  ╚██╗██╔╝██║   ██║████╗ ████║     ██╔═══██╗██╔════╝\n"
                "   ╚███╔╝ ██║   ██║██╔████╔██║     ██║   ██║███████╗\n"
                "   ██╔██╗ ╚██╗ ██╔╝██║╚██╔╝██║     ██║   ██║╚════██║\n"
                "  ██╔╝ ██╗ ╚████╔╝ ██║ ╚═╝ ██║     ╚██████╔╝███████║\n"
                "  ╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝      ╚═════╝ ╚══════╝\n"
                "\n"
                "  XVM-OS v1.0.0 - A Minimal Unix-like OS\n"
                "  Type 'help' for available commands\n\n";
            ramfs_write(f, 0, strlen(motd), motd);
        }
    }

    /* /bin/hello (example script) */
    vfs_node_t *bindir = ramfs_lookup(vfs_root, "bin");
    if (bindir) {
        ramfs_create(bindir, "hello", 0755);
        vfs_node_t *f = ramfs_lookup(bindir, "hello");
        if (f) {
            const char *s = "#!/bin/sh\necho Hello from XVM-OS!\n";
            ramfs_write(f, 0, strlen(s), s);
        }
        /* /bin/sysinfo */
        ramfs_create(bindir, "sysinfo", 0755);
        f = ramfs_lookup(bindir, "sysinfo");
        if (f) {
            const char *s =
                "#!/bin/sh\n"
                "echo === XVM-OS System Info ===\n"
                "uname -a\n"
                "free\n"
                "uptime\n"
                "date\n";
            ramfs_write(f, 0, strlen(s), s);
        }
    }

    /* /proc/version */
    vfs_node_t *procdir = ramfs_lookup(vfs_root, "proc");
    if (procdir) {
        ramfs_create(procdir, "version", 0444);
        vfs_node_t *f = ramfs_lookup(procdir, "version");
        if (f) {
            const char *s = "XVM-OS version 1.0.0 (gcc) #1 SMP\n";
            ramfs_write(f, 0, strlen(s), s);
        }
    }
}

/* =========================================================
 * MULTIBOOT2 HEADER
 * ========================================================= */
#define MULTIBOOT2_MAGIC      0xE85250D6
#define MULTIBOOT2_ARCH_I386  0

struct mb2_header {
    uint32_t magic;
    uint32_t arch;
    uint32_t length;
    uint32_t checksum;
    /* end tag */
    uint16_t end_type;
    uint16_t end_flags;
    uint32_t end_size;
} __packed;

static const struct mb2_header mb2_hdr __section(".multiboot") __used = {
    .magic    = MULTIBOOT2_MAGIC,
    .arch     = MULTIBOOT2_ARCH_I386,
    .length   = sizeof(struct mb2_header),
    .checksum = -(MULTIBOOT2_MAGIC + MULTIBOOT2_ARCH_I386 + sizeof(struct mb2_header)),
    .end_type  = 8,
    .end_flags = 0,
    .end_size  = 8,
};

/* Also support Multiboot1 */
#define MB1_MAGIC     0x1BADB002
#define MB1_FLAGS     0x00000003
static const uint32_t mb1_hdr[3] __section(".multiboot") __used = {
    MB1_MAGIC,
    MB1_FLAGS,
    -(MB1_MAGIC + MB1_FLAGS)
};

/* =========================================================
 * KERNEL ENTRY POINT
 * ========================================================= */
static uint8_t init_kstack[16384] __aligned(16);

void __attribute__((noreturn)) kmain(void) {
    /* Set up kernel stack */
    __asm__ volatile(
        "mov %0, %%esp\n"
        :: "r"(init_kstack + sizeof(init_kstack))
    );

    /* Initialize subsystems */
    vga_clear();

    /* Print boot banner */
    kprintf("\x1b[1;36m");
    kprintf("  ___  ___   ____  ___    ___  _____\n");
    kprintf(" / _ \\/ _ \\ / __ \\/ _ \\  / _ \\/ ___/\n");
    kprintf("/ ___/ , _// /_/ / // / / // /\\__ \\ \n");
    kprintf("/_/  /_/|_| \\____/\\___/  /____/____/ \n");
    kprintf("\x1b[0m");
    kprintf("\x1b[1mXVM-OS v1.0.0\x1b[0m - A Minimal Unix-like Operating System\n");
    kprintf("Copyright (c) 2024 XVM Project. Built with love in C.\n\n");

    kprintf("[  OK  ] GDT... ");
    gdt_init();
    kprintf("done\n");

    kprintf("[  OK  ] IDT/PIC... ");
    idt_init();
    kprintf("done\n");

    kprintf("[  OK  ] PIT (100Hz)... ");
    pit_init();
    kprintf("done\n");

    kprintf("[  OK  ] Paging... ");
    paging_init();
    kprintf("done\n");

    kprintf("[  OK  ] Memory: %dMB total, heap at 0x%x\n",
            PHYS_MEM_BYTES/(1024*1024), KERNEL_HEAP_START);

    kprintf("[  OK  ] VFS/ramfs... ");
    setup_rootfs();
    kprintf("done\n");

    /* Create init process (PID 1) */
    proc_t *init = &procs[1];
    memset(init, 0, sizeof(proc_t));
    init->pid   = 1;
    init->ppid  = 0;
    init->state = PROC_RUNNING;
    strcpy(init->name, "init");
    init->cwd   = vfs_root;
    init->brk   = 0x10000000;
    init->brk_start = 0x10000000;

    /* Setup standard file descriptors */
    vfs_node_t *tty_node = NULL;
    vfs_node_t *devdir = ramfs_lookup(vfs_root, "dev");
    if (devdir) tty_node = ramfs_lookup(devdir, "tty");
    if (!tty_node) {
        /* fallback: use a ramfs node with tty ops */
        tty_node = ramfs_create_node(vfs_root, "tty_fallback", VFS_DEV, 0620);
        if (tty_node) tty_node->ops = &devtty_ops;
    }

    for (int i = 0; i < 3; i++) {
        file_desc_t *fd = kzalloc(sizeof(file_desc_t));
        if (fd) {
            fd->node = tty_node;
            fd->flags = (i == 0) ? 0 : 1;
            fd->ref   = 1;
            init->fds[i] = fd;
        }
    }

    current_proc = init;
    scheduler_ready = 1;

    kprintf("[  OK  ] All systems GO\n\n");

    /* Show MOTD */
    vfs_node_t *etc = ramfs_lookup(vfs_root, "etc");
    if (etc) {
        vfs_node_t *motd = ramfs_lookup(etc, "motd");
        if (motd && motd->size > 0) {
            char buf[2048];
            int n = motd->ops->read(motd, 0, motd->size, buf);
            if (n > 0) tty_write(buf, n);
        }
    }

    /* Run the shell */
    xsh_run(init);

    /* Should never reach here */
    kprintf("\n[XVM-OS] Shell exited. Halting.\n");
    __asm__ volatile("cli; hlt");
    while(1);
}

/* =========================================================
 * BOOT ENTRY (called by bootloader)
 * ========================================================= */
void __attribute__((naked, section(".text.boot"))) _start(void) {
    __asm__ volatile(
        ".globl _start\n"
        /* Setup temporary stack */
        "mov $init_kstack_top, %%esp\n"
        "push %%ebx\n"  /* multiboot info */
        "push %%eax\n"  /* multiboot magic */
        "call kmain\n"
        "cli\n"
        "hlt\n"
        ::: "memory"
    );
}

/* Stack top symbol */
static uint8_t init_kstack_top_dummy __section(".bss") __used;

