#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
//#include <Library/UefiDevicePathLib.h>

#include <Protocol/DiskIo.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/DiskInfo.h>

#include <Guid/FileSystemVolumeLabelInfo.h>
#include <IndustryStandard/Mbr.h>

#define OSREVOCERY_PARTITION_VOL_LABEL L"BACK_UP"

typedef struct {
  EFI_HANDLE   BackupPartition;
  UINT32       PartitionNum;
  
  UINT8        MBRType;
  UINT8        UniqueMbrSig[4];
  EFI_HANDLE   BackupDisk;
} OS_RECOVERY_PRIVATE_DATA;

OS_RECOVERY_PRIVATE_DATA  *mPrivateData = NULL;

#ifdef  EFIC_DEBUG_HAHA

EFI_STATUS
EFIAPI
OsRecoveryDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                  Status;
  EFI_LOADED_IMAGE_PROTOCOL   *LoadedImage = NULL;


  // 
  // Retrieve the Loaded Image Protocol from image handle 
  // 
  Status = gBS->OpenProtocol (
                          ImageHandle,
                          &gEfiLoadedImageProtocolGuid,
                          (VOID **)&LoadedImage,
                          ImageHandle,
                          ImageHandle,
                          EFI_OPEN_PROTOCOL_GET_PROTOCOL
                          ); 
  if (EFI_ERROR (Status)) { 
    return Status; 
  }
  
  //
  //  Retrieve Simple File System Protocol
  //
  Status = gBS->LocateProtocol (
                 &gEfiSimpleFileSystemProtocolGuid, 
                 NULL, 
                 &mSimpleFileSystem
                 );
  if (EFI_ERROR(Status))
  {
    return Status;
  }
  
  LoadedImage->Unload = eScreenShotDriverUnload; 

  Status = RegisterSnapHotKey (SCAN_F2);

  return EFI_SUCCESS; 
}

/**
 Unload function of this driver

 @param[in]         ImageHandle    - Handle of this image            
 
 @retval EFI Status                  
*/
EFI_STATUS
EFIAPI
OsRecoveryDxeDriverUnload ( 
  IN EFI_HANDLE  ImageHandle 
  )
{
  EFI_STATUS Status;

  Status = EFI_SUCCESS;

  return Status;
}
#endif

BOOLEAN
EfiGrowBuffer (
  IN OUT EFI_STATUS   *Status,
  IN OUT VOID         **Buffer,
  IN UINTN            BufferSize
  )
{
  BOOLEAN TryAgain;

  //
  // If this is an initial request, buffer will be null with a new buffer size
  //
  if ((*Buffer == NULL) && (BufferSize != 0)) {
    *Status = EFI_BUFFER_TOO_SMALL;
  }
  //
  // If the Status code is "buffer too small", resize the buffer
  //
  TryAgain = FALSE;
  if (*Status == EFI_BUFFER_TOO_SMALL) {

    if (*Buffer != NULL) {
      FreePool (*Buffer);
    }

    *Buffer = AllocateZeroPool (BufferSize);

    if (*Buffer != NULL) {
      TryAgain = TRUE;
    } else {
      *Status = EFI_OUT_OF_RESOURCES;
    }
  }
  //
  // If there's an error, free the buffer
  //
  if (!TryAgain && EFI_ERROR (*Status) && (*Buffer != NULL)) {
    FreePool (*Buffer);
    *Buffer = NULL;
  }

  return TryAgain;
}

EFI_FILE_SYSTEM_VOLUME_LABEL *
EfiLibFileSystemVolumeLabelInfo (
  IN EFI_FILE_HANDLE      FHand
  )
{
  EFI_STATUS                        Status;
  EFI_FILE_SYSTEM_VOLUME_LABEL      *Buffer;
  UINTN                             BufferSize;
  //
  // Initialize for GrowBuffer loop
  //
  Buffer      = NULL;
  BufferSize  = SIZE_OF_EFI_FILE_SYSTEM_VOLUME_LABEL + 200;

  //
  // Call the real function
  //
  while (EfiGrowBuffer (&Status, (VOID **) &Buffer, BufferSize)) {
    Status = FHand->GetInfo (
                      FHand,
                      &gEfiFileSystemVolumeLabelInfoIdGuid,
                      &BufferSize,
                      Buffer
                      );
  }

  return Buffer;
}

  
EFI_STATUS
FindBackupPartition (
  VOID
  )
{
  EFI_STATUS       Status;
  EFI_HANDLE       *HandlePointer;
  UINTN            HandleCount;
  EFI_BLOCK_IO     *BlkIo;
  EFI_DEVICE_PATH  *DevicePath;
  UINTN            PathSize;
  BOOLEAN          IsBackupPartition;
  EFI_DEVICE_PATH  *PathInstance;
  UINTN            i;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Volume = NULL;
  EFI_FILE_PROTOCOL                *Root = NULL;
  EFI_FILE_SYSTEM_VOLUME_LABEL     *VolLabel = NULL;
  UINTN            Count;
  EFI_HANDLE       PartitionHandle = 0;
  
  Count = 0;
  //
  // Try to find all of the hard disks by finding all
  // handles that support BlockIo protocol
  //
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandlePointer
                  );
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  for (i = 0; i < HandleCount; i++) {
    IsBackupPartition = TRUE;

    Status = gBS->HandleProtocol(HandlePointer[i], &gEfiSimpleFileSystemProtocolGuid, &Volume);
    if (EFI_ERROR(Status)) {
      IsBackupPartition = FALSE;
    } else {
      //OSREVOCERY_PARTITION_VOL_LABEL
      Root = NULL;
      Status = Volume->OpenVolume (Volume, &Root);
      if (EFI_ERROR (Status)) {
        IsBackupPartition = FALSE;
      }
      else {
        VolLabel = EfiLibFileSystemVolumeLabelInfo (Root);
        if (StrCmp(OSREVOCERY_PARTITION_VOL_LABEL, VolLabel->VolumeLabel) != 0) {
          IsBackupPartition = FALSE;
        }
        //Print (L"VolLabel: %s\n", VolLabel!=NULL?VolLabel->VolumeLabel:L"NULL");
      }
    }
    
    Status = gBS->HandleProtocol(HandlePointer[i], &gEfiBlockIoProtocolGuid, &BlkIo);
    if (BlkIo->Media->RemovableMedia) {
      IsBackupPartition = FALSE;
    }
    else if ( ! BlkIo->Media->MediaPresent) {
      IsBackupPartition = FALSE;
    }
    else if (BlkIo->Media->ReadOnly) {
      IsBackupPartition = FALSE;
    }

    ///@todo: backup partition must be a main partition!!!

    if (IsBackupPartition) {
      //
      // Return this handle
      //
      PartitionHandle = HandlePointer[i];
      Count++;
    }
  }
  if (Count == 0) {
    return EFI_NOT_FOUND;
  }
  else if (Count > 1) {
    return EFI_DEVICE_ERROR;
  }
  else {
    HARDDRIVE_DEVICE_PATH      *HardDrive;
    
    mPrivateData->BackupPartition = PartitionHandle;
    DevicePath = DevicePathFromHandle(PartitionHandle);
    while (DevicePath != NULL) {
      PathInstance = GetNextDevicePathInstance(&DevicePath, &PathSize);

      while (!IsDevicePathEnd(PathInstance)) {
        if (DevicePathType (PathInstance) == MEDIA_DEVICE_PATH &&
            DevicePathSubType (PathInstance) == MEDIA_HARDDRIVE_DP) {
          HardDrive = (HARDDRIVE_DEVICE_PATH *)PathInstance;
          CopyMem ((VOID *)mPrivateData->UniqueMbrSig, (VOID *)HardDrive->Signature, 4);
          mPrivateData->PartitionNum = HardDrive->PartitionNumber;
          mPrivateData->MBRType = HardDrive->MBRType;
          //break;
        }

        PathInstance = NextDevicePathNode(PathInstance);
      }
    }
  }
  return EFI_SUCCESS;
}

EFI_STATUS
FindBackupDisk (
  VOID
  )
{
  EFI_STATUS            Status;
  EFI_HANDLE            *HandlePointer;
  UINTN                 HandleCount;
  EFI_BLOCK_IO          *BlkIo;
  EFI_DISK_IO_PROTOCOL  *DiskIo = NULL;
  EFI_DEVICE_PATH       *DevicePath;
  UINTN                 PathSize;
  BOOLEAN               Partitionable;
  EFI_DEVICE_PATH       *PathInstance;
  UINTN                 i;
  EFI_HANDLE            TempDiskHandle = 0;
  UINTN                 Count = 0;
  MASTER_BOOT_RECORD    *Mbr = NULL;

  
  if (mPrivateData->BackupPartition == 0 || *(UINT32 *)mPrivateData->UniqueMbrSig == 0 ) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Try to find all of the hard disks by finding all
  // handles that support BlockIo protocol
  //
  Status = gBS->LocateHandleBuffer(
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandlePointer
                  );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  for (i = 0; i < HandleCount; i++) {
    Partitionable = TRUE;
    Status = gBS->HandleProtocol (HandlePointer[i], &gEfiBlockIoProtocolGuid, &BlkIo);
    if (EFI_ERROR(Status)) {
      Partitionable = FALSE;
    }
    Status = gBS->HandleProtocol (HandlePointer[i], &gEfiDiskIoProtocolGuid, &DiskIo);
    if (EFI_ERROR(Status)) {
      Partitionable = FALSE;
    }

    if (BlkIo->Media->RemovableMedia) {
      Partitionable = FALSE;
    }
    if ( ! BlkIo->Media->MediaPresent) {
      Partitionable = FALSE;
    }
    if (BlkIo->Media->ReadOnly) {
      Partitionable = FALSE;
    }

    //
    // OK, it seems to be a present, fixed, read/write, block device.
    // Now, make sure it's really the raw device by inspecting the
    // device path.
    //
    DevicePath = DevicePathFromHandle(HandlePointer[i]);
    while (DevicePath != NULL) {
      PathInstance = GetNextDevicePathInstance(&DevicePath, &PathSize);

      while (!IsDevicePathEnd(PathInstance)) {
        if ((DevicePathType(PathInstance) == MEDIA_DEVICE_PATH)) {
          Partitionable = FALSE;
        }

        PathInstance = NextDevicePathNode(PathInstance);
      }
    }

    if (Partitionable) {
      //
      // Return this handle
      //
      
      Mbr = AllocatePool (BlkIo->Media->BlockSize);
      if (Mbr == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }
      Status = DiskIo->ReadDisk (
                       DiskIo,
                       BlkIo->Media->MediaId,//MediaId,
                       0,
                       BlkIo->Media->BlockSize,//BlockSize,
                       Mbr
                       );
      if (EFI_ERROR(Status) || Mbr->Signature != 0xaa55) {
        // MBR is invalid
      }
      else if (*(UINT32 *)mPrivateData->UniqueMbrSig != *(UINT32 *)Mbr->UniqueMbrSignature) {
        //Print (L" UniqueMbrSignature=0x%08X (NOT IDENTICAL!!!)\n", *(UINT32 *)Mbr->UniqueMbrSignature);
      }
      else {
        // UniqueMbrSignature identical
        //Print (L" UniqueMbrSignature=0x%08X\n", *(UINT32 *)Mbr->UniqueMbrSignature);
        TempDiskHandle = HandlePointer[i];
        Count++;
      }
      if (Mbr != NULL) {
        FreePool (Mbr);
      }
    }
  }
  
  if (Count == 1) {
    mPrivateData->BackupDisk = TempDiskHandle;
    return EFI_SUCCESS;
  }
  else if (Count == 0) {
    return EFI_NOT_FOUND;
  }
  else {
    return EFI_DEVICE_ERROR;
  }
}

EFI_STATUS
DumpAllBlockIo (
  VOID
  )
{
  EFI_STATUS      Status = EFI_SUCCESS;
  UINTN           HandleCount;
  EFI_HANDLE      *HandleBuffer;
  UINTN           Index;
  EFI_BLOCK_IO_PROTOCOL  *BlockIo = NULL;
  EFI_DEVICE_PATH        *DevicePath;
  EFI_DISK_INFO_PROTOCOL    *DiskInfo;
  UINT32                    IdeChannel = 0;
  UINT32                    IdeDevice = 0;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  for (Index = 0; Index < HandleCount; Index++) {
    DevicePath = DevicePathFromHandle(HandleBuffer[Index]);
    Print(L"%s\n",ConvertDevicePathToText (DevicePath, TRUE, TRUE));
    Status = gBS->HandleProtocol(HandleBuffer[Index], &gEfiBlockIoProtocolGuid, &BlockIo);
    ASSERT (Status == EFI_SUCCESS);
    if (!BlockIo->Media->MediaPresent || BlockIo->Media->RemovableMedia) {
      continue;//ericdebug Print (L"  Media Not Present!!!");
    }
    else {
      Print(L"  Logical?:%s  Removable?:%s  ",BlockIo->Media->LogicalPartition?L"TRUE":L"FALSE", BlockIo->Media->RemovableMedia?L"TRUE":L"FALSE");
      //Print(L"  BlockSize:%s\n",BlockIo->Media->LogicalPartition?L"TRUE":L"FALSE");
    }
    Status = gBS->HandleProtocol (HandleBuffer[Index], &gEfiDiskInfoProtocolGuid, (VOID **)&DiskInfo);
    if (EFI_ERROR(Status)) {
      Print (L"  Have No DiskInfo!!!  ");
    }
    else {
      Status = DiskInfo->WhichIde (DiskInfo, &IdeChannel, &IdeDevice);
      if (!EFI_ERROR (Status)) {
        Print (L"  DiskInfo:  IdeChannel=%d, IdeDevice=%d", IdeChannel, IdeDevice);
      }
    }
    Print (L"\n");
  }
  
  return Status;    
}

EFI_STATUS
ActivateBackupPartition (
  VOID
  )
{
  EFI_STATUS             Status;
  UINTN                  Index;
  EFI_DISK_IO_PROTOCOL   *DiskIo = NULL;
  EFI_BLOCK_IO_PROTOCOL  *BlockIo = NULL;
  MASTER_BOOT_RECORD     *Mbr = NULL;

  Status = gBS->HandleProtocol (mPrivateData->BackupDisk, &gEfiBlockIoProtocolGuid, &BlockIo);
  Status = gBS->HandleProtocol (mPrivateData->BackupDisk, &gEfiDiskIoProtocolGuid, &DiskIo);
  Mbr = AllocatePool (BlockIo->Media->BlockSize);
  if (Mbr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  Status = DiskIo->ReadDisk (
                      DiskIo,
                      BlockIo->Media->MediaId,
                      0,
                      BlockIo->Media->BlockSize,
                      Mbr
                      );
  if (Mbr->Signature == 0xaa55) {
    Print (L" MediaId=%d BlockSize=0x%08X Signature=0x%04X UniqueMbrSignature=0x%02X%02X%02X%02X\n",
           BlockIo->Media->MediaId,
           BlockIo->Media->BlockSize,
           Mbr->Signature,
           Mbr->UniqueMbrSignature[3],  Mbr->UniqueMbrSignature[2],  Mbr->UniqueMbrSignature[1],  Mbr->UniqueMbrSignature[0]
          );
    Print (L"  BootIndicator:");
    for (Index = 0; Index < MAX_MBR_PARTITIONS; Index++) {
      Print (L" [0x%02X] ",
        Mbr->Partition[Index].BootIndicator
        );
      Mbr->Partition[Index].BootIndicator++;//ericdebug
    }
    Print (L"\n");
    Status = DiskIo->WriteDisk (
                     DiskIo,
                     BlockIo->Media->MediaId,
                     0,
                     BlockIo->Media->BlockSize,
                     Mbr
                     );
  }
  if (Mbr != NULL) {
    FreePool (Mbr);
  }
  
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS      Status;
  UINTN           Index;
  
  EFI_DISK_IO_PROTOCOL             *DiskIo = NULL;
  EFI_BLOCK_IO_PROTOCOL            *BlockIo = NULL;
  
  MASTER_BOOT_RECORD        *Mbr = NULL;
    
  mPrivateData = AllocateZeroPool (sizeof (OS_RECOVERY_PRIVATE_DATA));
  if (mPrivateData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  Status = FindBackupPartition ();//ERICDEBUG
  Status = FindBackupDisk(); //ericdebug
  Status = gBS->HandleProtocol (mPrivateData->BackupDisk, &gEfiBlockIoProtocolGuid, &BlockIo);
  Status = gBS->HandleProtocol (mPrivateData->BackupDisk, &gEfiDiskIoProtocolGuid, &DiskIo);
  Mbr = AllocatePool (BlockIo->Media->BlockSize);
  if (Mbr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  Status = DiskIo->ReadDisk (
                      DiskIo,
                      BlockIo->Media->MediaId,//MediaId,
                      0,//ericdebug**0,
                      BlockIo->Media->BlockSize,//BlockSize,
                      Mbr
                      );
  if (Mbr->Signature == 0xaa55) {
    Print (L" MediaId=%d BlockSize=0x%08X Signature=0x%04X UniqueMbrSignature=0x%02X%02X%02X%02X\n",
           BlockIo->Media->MediaId,
           BlockIo->Media->BlockSize,
           Mbr->Signature,
           Mbr->UniqueMbrSignature[3],  Mbr->UniqueMbrSignature[2],  Mbr->UniqueMbrSignature[1],  Mbr->UniqueMbrSignature[0]
          );
    Print (L"  BootIndicator:");
    for (Index = 0; Index < MAX_MBR_PARTITIONS; Index++) {
      Print (L" [0x%02X] ",
        Mbr->Partition[Index].BootIndicator
        );
      Mbr->Partition[Index].BootIndicator++;//ericdebug
    }
    Print (L"\n");

  }
  if (Mbr != NULL) {
    FreePool (Mbr);
  }

  //Status = DumpAllBlockIo();//ericdebug  
  return Status;
}
//PartitionInstallMbrChildHandles
