// Copyright 2016 jeonghun

#include "hook.h"
#include <windows.h>
#include <stdio.h>

typedef int(__cdecl *fseek_fptr_t)(FILE*, long, int);
static fseek_fptr_t fseek_fptr = NULL;
static IMAGE_THUNK_DATA *thunk_ptr_backup = 0;

static void iat_hook(IMAGE_THUNK_DATA *thunk_ptr, void *func_ptr, BOOL backup) {
  if (thunk_ptr != NULL && func_ptr != NULL) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (VirtualQuery(thunk_ptr, &mbi, sizeof(mbi)) > 0) {
      if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect) != FALSE) {
        if (backup != FALSE) {
          thunk_ptr_backup = thunk_ptr;
          fseek_fptr = (fseek_fptr_t)thunk_ptr->u1.Function;
        }
        InterlockedExchangePointer(&thunk_ptr->u1.Function, func_ptr);
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect);
      }
    }
  }
}

static BOOL get_org_filesize(int *length_ptr) {
  BOOL size_exist = FALSE;
  if (length_ptr != NULL) {
    HMODULE hmod = GetModuleHandle(NULL);
    HRSRC hrsrc = FindResource(hmod, MAKEINTRESOURCE(1), "BINARYSIZE");
    if (hrsrc != NULL) {
      DWORD rsc_size = SizeofResource(hmod, hrsrc);
      if (rsc_size == sizeof(DWORD)) {
        *length_ptr = *(DWORD*)LockResource(LoadResource(hmod, hrsrc));
        size_exist = TRUE;
      }
    }
  }
  return size_exist;
}

static int __cdecl fseek_hook(FILE* _Stream, long _Offset, int _Origin) {
  const long ZIP_EOCD_OFFSET = -22;

  if (fseek_fptr != NULL && _Origin == SEEK_END && _Offset == ZIP_EOCD_OFFSET) {
    int filesize = 0;
    if (get_org_filesize(&filesize) != FALSE) {
      _Offset = filesize + ZIP_EOCD_OFFSET;
      _Origin = SEEK_SET;
      iat_hook(thunk_ptr_backup, fseek_fptr, FALSE);
    }
  }
  return fseek_fptr(_Stream, _Offset, _Origin);
}

void hook(unsigned long *func_ref) {
  iat_hook((IMAGE_THUNK_DATA*)func_ref, fseek_hook, TRUE);
}
