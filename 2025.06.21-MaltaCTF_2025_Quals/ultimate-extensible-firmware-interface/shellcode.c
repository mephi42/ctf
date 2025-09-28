#include <efi.h>
#include <efilib.h>

__attribute__((section(".entry"))) void entry(void) {
  EFI_HANDLE ImageHandle = (EFI_HANDLE)0x2844e18;
  EFI_SYSTEM_TABLE *SystemTable = (EFI_SYSTEM_TABLE *)0x35ec018;
  EFI_LOADED_IMAGE *LoadedImage;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *RootDir;
  EFI_FILE_PROTOCOL *File;
  CHAR16 FileName[] = u"\\flag.txt"; // UEFI uses Windows-style paths
  UINTN BufferSize;
  CHAR8 Buffer[1024];
  CHAR16 Buffer16[1024];
  EFI_GUID LoadedImageProtocolGuid = {
      0x5B1B31A1,
      0x9562,
      0x11d2,
      {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}};
  EFI_GUID SimpleFileSystemProtocolGuid = {
      0x964e5b22,
      0x6459,
      0x11d2,
      {0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};

  SystemTable->BootServices->HandleProtocol(
      ImageHandle, &LoadedImageProtocolGuid, (void **)&LoadedImage);
  SystemTable->BootServices->HandleProtocol(LoadedImage->DeviceHandle,
                                            &SimpleFileSystemProtocolGuid,
                                            (void **)&FileSystem);
  FileSystem->OpenVolume(FileSystem, &RootDir);
  RootDir->Open(RootDir, &File, FileName, EFI_FILE_MODE_READ, 0);
  BufferSize = sizeof(Buffer);
  File->Read(File, &BufferSize, Buffer);
  for (UINTN i = 0; i < BufferSize; ++i) {
    Buffer16[i] = Buffer[i];
  }
  SystemTable->ConOut->OutputString(SystemTable->ConOut, Buffer16);
}