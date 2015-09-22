// Copyright 2010-2012 The W32 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package w32

import (
	"syscall"
	"unsafe"
)

var (
	modntdll = syscall.NewLazyDLL("ntdll.dll")

	procNtQueryInformationProcess = modntdll.NewProc("NtQueryInformationProcess")
)

const ( // for NtQueryInformationProcess (processInformationClass)
	ProcessBasicInformation = 0
)

// []byte if successful, nil otherwise
func NtQueryInformationProcess(hProcess HANDLE, processInformationClass int, length int) []byte {
	buf := make([]byte, length)
	retLen := int(0)
	ret, _, _ := procNtQueryInformationProcess.Call(
		uintptr(hProcess),
		uintptr(processInformationClass),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)))
	if ret != 0 || retLen != len(buf) {
		return nil
	}
	return buf
}
