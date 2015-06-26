// Copyright 2010-2012 The W32 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package w32

import (
	"syscall"
	"unsafe"
)

var (
	modpsapi = syscall.NewLazyDLL("psapi.dll")

	procEnumProcesses        = modpsapi.NewProc("EnumProcesses")
	procGetProcessMemoryInfo = modpsapi.NewProc("GetProcessMemoryInfo")
)

func EnumProcesses(processIds []uint32, cb uint32, bytesReturned *uint32) bool {
	ret, _, _ := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&processIds[0])),
		uintptr(cb),
		uintptr(unsafe.Pointer(bytesReturned)))

	return ret != 0
}

func GetProcessMemoryInfo(process HANDLE) (PROCESS_MEMORY_COUNTERS, bool) {
	output := PROCESS_MEMORY_COUNTERS{}
	cb := unsafe.Sizeof(output)
	ret, _, _ := procGetProcessMemoryInfo.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(&output)),
		cb,
	)

	return output, ret != 0
}

type PROCESS_MEMORY_COUNTERS struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}
