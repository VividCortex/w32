// Copyright 2010-2012 The W32 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package w32

import (
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetModuleHandle            = modkernel32.NewProc("GetModuleHandleW")
	procMulDiv                     = modkernel32.NewProc("MulDiv")
	procGetConsoleWindow           = modkernel32.NewProc("GetConsoleWindow")
	procGetCurrentThread           = modkernel32.NewProc("GetCurrentThread")
	procGetLogicalDrives           = modkernel32.NewProc("GetLogicalDrives")
	procGetLogicalDriveStrings     = modkernel32.NewProc("GetLogicalDriveStringsA")
	procGetUserDefaultLCID         = modkernel32.NewProc("GetUserDefaultLCID")
	procLstrlen                    = modkernel32.NewProc("lstrlenW")
	procLstrcpy                    = modkernel32.NewProc("lstrcpyW")
	procGlobalAlloc                = modkernel32.NewProc("GlobalAlloc")
	procGlobalFree                 = modkernel32.NewProc("GlobalFree")
	procGlobalLock                 = modkernel32.NewProc("GlobalLock")
	procGlobalMemoryStatusEx       = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGlobalUnlock               = modkernel32.NewProc("GlobalUnlock")
	procMoveMemory                 = modkernel32.NewProc("RtlMoveMemory")
	procFindResource               = modkernel32.NewProc("FindResourceW")
	procSizeofResource             = modkernel32.NewProc("SizeofResource")
	procLockResource               = modkernel32.NewProc("LockResource")
	procLoadResource               = modkernel32.NewProc("LoadResource")
	procGetLastError               = modkernel32.NewProc("GetLastError")
	procOpenProcess                = modkernel32.NewProc("OpenProcess")
	procTerminateProcess           = modkernel32.NewProc("TerminateProcess")
	procCloseHandle                = modkernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot   = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procModule32First              = modkernel32.NewProc("Module32FirstW")
	procModule32Next               = modkernel32.NewProc("Module32NextW")
	procGetSystemTimes             = modkernel32.NewProc("GetSystemTimes")
	procGetConsoleScreenBufferInfo = modkernel32.NewProc("GetConsoleScreenBufferInfo")
	procSetConsoleTextAttribute    = modkernel32.NewProc("SetConsoleTextAttribute")
	procGetDiskFreeSpaceEx         = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procGetProcessTimes            = modkernel32.NewProc("GetProcessTimes")
	procGetProcessIoCounters       = modkernel32.NewProc("GetProcessIoCounters")
	procSetSystemTime              = modkernel32.NewProc("SetSystemTime")
	procGetSystemTime              = modkernel32.NewProc("GetSystemTime")
	procFileTimeToSystemTime       = modkernel32.NewProc("FileTimeToSystemTime")
	procWaitForSingleObject        = modkernel32.NewProc("WaitForSingleObject")
	procQueryFullProcessImageName  = modkernel32.NewProc("QueryFullProcessImageNameW")
	procReadProcessMemory          = modkernel32.NewProc("ReadProcessMemory")
)

func GetModuleHandle(modulename string) HINSTANCE {
	var mn uintptr
	if modulename == "" {
		mn = 0
	} else {
		mn = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(modulename)))
	}
	ret, _, _ := procGetModuleHandle.Call(mn)
	return HINSTANCE(ret)
}

func MulDiv(number, numerator, denominator int) int {
	ret, _, _ := procMulDiv.Call(
		uintptr(number),
		uintptr(numerator),
		uintptr(denominator))

	return int(ret)
}

func GetConsoleWindow() HWND {
	ret, _, _ := procGetConsoleWindow.Call()

	return HWND(ret)
}

func GetCurrentThread() HANDLE {
	ret, _, _ := procGetCurrentThread.Call()

	return HANDLE(ret)
}

func GetLogicalDrives() uint32 {
	ret, _, _ := procGetLogicalDrives.Call()

	return uint32(ret)
}

func GetLogicalDriveStrings() (uint32, []byte) {
	lpBuffer := [512]byte{}
	lpBuffer[0] = 0
	ret, _, _ := procGetLogicalDriveStrings.Call(uintptr(len(lpBuffer)-1), uintptr(unsafe.Pointer(&lpBuffer)))

	return uint32(ret), lpBuffer[:]
}

func GetUserDefaultLCID() uint32 {
	ret, _, _ := procGetUserDefaultLCID.Call()

	return uint32(ret)
}

func Lstrlen(lpString *uint16) int {
	ret, _, _ := procLstrlen.Call(uintptr(unsafe.Pointer(lpString)))

	return int(ret)
}

func Lstrcpy(buf []uint16, lpString *uint16) {
	procLstrcpy.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(lpString)))
}

func GlobalAlloc(uFlags uint, dwBytes uint32) HGLOBAL {
	ret, _, _ := procGlobalAlloc.Call(
		uintptr(uFlags),
		uintptr(dwBytes))

	if ret == 0 {
		panic("GlobalAlloc failed")
	}

	return HGLOBAL(ret)
}

func GlobalFree(hMem HGLOBAL) {
	ret, _, _ := procGlobalFree.Call(uintptr(hMem))

	if ret != 0 {
		panic("GlobalFree failed")
	}
}

func GlobalLock(hMem HGLOBAL) unsafe.Pointer {
	ret, _, _ := procGlobalLock.Call(uintptr(hMem))

	if ret == 0 {
		panic("GlobalLock failed")
	}

	return unsafe.Pointer(ret)
}

func GlobalMemoryStatusEx(lpBuffer *LPMEMORYSTATUSEX) bool {
	// Set the size of the input struct before calling api func
	lpBuffer.dwLength = uint32(unsafe.Sizeof(*lpBuffer))
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(lpBuffer)))

	return ret != 0
}

func GlobalUnlock(hMem HGLOBAL) bool {
	ret, _, _ := procGlobalUnlock.Call(uintptr(hMem))

	return ret != 0
}

func MoveMemory(destination, source unsafe.Pointer, length uint32) {
	procMoveMemory.Call(
		uintptr(unsafe.Pointer(destination)),
		uintptr(source),
		uintptr(length))
}

func FindResource(hModule HMODULE, lpName, lpType *uint16) (HRSRC, error) {
	ret, _, _ := procFindResource.Call(
		uintptr(hModule),
		uintptr(unsafe.Pointer(lpName)),
		uintptr(unsafe.Pointer(lpType)))

	if ret == 0 {
		return 0, syscall.GetLastError()
	}

	return HRSRC(ret), nil
}

func SizeofResource(hModule HMODULE, hResInfo HRSRC) uint32 {
	ret, _, _ := procSizeofResource.Call(
		uintptr(hModule),
		uintptr(hResInfo))

	if ret == 0 {
		panic("SizeofResource failed")
	}

	return uint32(ret)
}

func LockResource(hResData HGLOBAL) unsafe.Pointer {
	ret, _, _ := procLockResource.Call(uintptr(hResData))

	if ret == 0 {
		panic("LockResource failed")
	}

	return unsafe.Pointer(ret)
}

func LoadResource(hModule HMODULE, hResInfo HRSRC) HGLOBAL {
	ret, _, _ := procLoadResource.Call(
		uintptr(hModule),
		uintptr(hResInfo))

	if ret == 0 {
		panic("LoadResource failed")
	}

	return HGLOBAL(ret)
}

func GetLastError() uint32 {
	ret, _, _ := procGetLastError.Call()
	return uint32(ret)
}

const (
	// Generic access rights
	GAR_ALL     = 0x10000000 // All possible access rights
	GAR_EXECUTE = 0x20000000 // Execute access
	GAR_WRITE   = 0x40000000 // Write access
	GAR_READ    = 0x80000000 // Read access

	// Standard access rights
	SAR_DELETE       = 0x00010000 // The right to delete the object.
	SAR_READ_CONTROL = 0x00020000 // The right to read the information in the object's security descriptor, not including the information in the system access control list (SACL).
	SAR_WRITE_DAC    = 0x00040000 // The right to modify the discretionary access control list (DACL) in the object's security descriptor.
	SAR_WRITE_OWNER  = 0x00080000 // The right to change the owner in the object's security descriptor.
	SAR_SYNCHRONIZE  = 0x00100000 // The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state.

	// Security
	ACCESS_SYSTEM_SECURITY = 0x01000000 // ability to get or set the SACL in an object's security descriptor

	// Process-specific access rights
	PROCESS_TERMINATE                 = 0x0001 // Required to terminate a process using TerminateProcess.
	PROCESS_CREATE_THREAD             = 0x0002 // Required to create a thread.
	PROCESS_SET_SESSIONID             = 0x0004 // [undoc].
	PROCESS_VM_OPERATION              = 0x0008 // Required to perform an operation on the address space of a process: VirtualProtectEx, WriteProcessMemory.
	PROCESS_VM_READ                   = 0x0010 // Required to read memory in a process using ReadProcessMemory.
	PROCESS_VM_WRITE                  = 0x0020 // Required to write to memory in a process using WriteProcessMemory.
	PROCESS_DUP_HANDLE                = 0x0040 // Required to duplicate a handle using DuplicateHandle.
	PROCESS_CREATE_PROCESS            = 0x0080 // Required to create a process.
	PROCESS_SET_QUOTA                 = 0x0100 // Required to set memory limits using SetProcessWorkingSetSize.
	PROCESS_SET_INFORMATION           = 0x0200 // Required to set certain information about a process, such as its priority class.
	PROCESS_QUERY_INFORMATION         = 0x0400 // Required to retrieve certain information about a process, such as its token, exit code, and priority class. Implies PROCESS_QUERY_LIMITED_INFORMATION.
	PROCESS_SUSPEND_RESUME            = 0x0800 // Required to suspend or resume a process.
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000 // Required to retrieve certain information about a process: GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName.
	PROCESS_SET_LIMITED_INFORMATION   = 0x2000 // [undoc].
)

func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (HANDLE, bool) {
	inherit := 0
	if inheritHandle {
		inherit = 1
	}

	ret, _, _ := procOpenProcess.Call(
		uintptr(desiredAccess),
		uintptr(inherit),
		uintptr(processId))
	return HANDLE(ret), ret != 0
}

const ( // for QueryFullProcessImageName
	PROCESS_NAME_WINPATH = 0x00000000 // C:\Windows\...
	PROCESS_NAME_NATIVE  = 0x00000001 // \Device\HarddiskVolume3\Windows\...
)

// Empty string on error.
func QueryFullProcessImageName(hProcess HANDLE, flags uint32) string {
	buf := make([]uint16, syscall.MAX_LONG_PATH+1)
	var bufsiz = uint32(len(buf))
	ret, _, _ := procQueryFullProcessImageName.Call(
		uintptr(hProcess),
		uintptr(flags),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufsiz)))
	if ret == 0 || bufsiz == 0 || bufsiz >= uint32(len(buf)) || buf[0] == 0 { // error
		return ""
	}
	return string(utf16.Decode(buf[:bufsiz]))
}

// returns length bytes, or nil if error
func ReadProcessMemory(hProcess HANDLE, addr uintptr, length int) []byte {
	buf := make([]byte, length)
	read := int(0)
	ret, _, _ := procReadProcessMemory.Call(uintptr(hProcess), addr,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(length), uintptr(unsafe.Pointer(&read)))
	if ret == 0 || read != length {
		return nil
	}
	return buf
}

func TerminateProcess(hProcess HANDLE, uExitCode uint) bool {
	ret, _, _ := procTerminateProcess.Call(
		uintptr(hProcess),
		uintptr(uExitCode))
	return ret != 0
}

func CloseHandle(object HANDLE) bool {
	ret, _, _ := procCloseHandle.Call(
		uintptr(object))
	return ret != 0
}

func CreateToolhelp32Snapshot(flags, processId uint32) HANDLE {
	ret, _, _ := procCreateToolhelp32Snapshot.Call(
		uintptr(flags),
		uintptr(processId))

	if ret <= 0 {
		return HANDLE(0)
	}

	return HANDLE(ret)
}

func Module32First(snapshot HANDLE, me *MODULEENTRY32) bool {
	ret, _, _ := procModule32First.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(me)))

	return ret != 0
}

func Module32Next(snapshot HANDLE, me *MODULEENTRY32) bool {
	ret, _, _ := procModule32Next.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(me)))

	return ret != 0
}

func GetSystemTimes(lpIdleTime, lpKernelTime, lpUserTime *FILETIME) bool {
	ret, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(lpIdleTime)),
		uintptr(unsafe.Pointer(lpKernelTime)),
		uintptr(unsafe.Pointer(lpUserTime)))

	return ret != 0
}

func GetProcessTimes(hProcess HANDLE, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime *FILETIME) bool {
	ret, _, _ := procGetProcessTimes.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(lpCreationTime)),
		uintptr(unsafe.Pointer(lpExitTime)),
		uintptr(unsafe.Pointer(lpKernelTime)),
		uintptr(unsafe.Pointer(lpUserTime)))

	return ret != 0
}

func GetProcessIoCounters(hprocess HANDLE) (IO_COUNTERS, bool) {
	output := IO_COUNTERS{}
	ret, _, _ := procGetProcessIoCounters.Call(
		uintptr(hprocess),
		uintptr(unsafe.Pointer(&output)),
	)

	return output, ret != 0
}

func GetConsoleScreenBufferInfo(hConsoleOutput HANDLE) *CONSOLE_SCREEN_BUFFER_INFO {
	var csbi CONSOLE_SCREEN_BUFFER_INFO
	ret, _, _ := procGetConsoleScreenBufferInfo.Call(
		uintptr(hConsoleOutput),
		uintptr(unsafe.Pointer(&csbi)))
	if ret == 0 {
		return nil
	}
	return &csbi
}

func SetConsoleTextAttribute(hConsoleOutput HANDLE, wAttributes uint16) bool {
	ret, _, _ := procSetConsoleTextAttribute.Call(
		uintptr(hConsoleOutput),
		uintptr(wAttributes))
	return ret != 0
}

func GetDiskFreeSpaceEx(dirName string) (r bool,
	freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64) {
	ret, _, _ := procGetDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(dirName))),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalNumberOfBytes)),
		uintptr(unsafe.Pointer(&totalNumberOfFreeBytes)))
	return ret != 0,
		freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes
}

func GetSystemTime() *SYSTEMTIME {
	var time SYSTEMTIME
	procGetSystemTime.Call(
		uintptr(unsafe.Pointer(&time)))
	return &time
}

func SetSystemTime(time *SYSTEMTIME) bool {
	ret, _, _ := procSetSystemTime.Call(
		uintptr(unsafe.Pointer(time)))
	return ret != 0
}

func FileTimeToSystemTime(time *FILETIME) (bool, *SYSTEMTIME) {
	var sysTime SYSTEMTIME
	ret, _, _ := procFileTimeToSystemTime.Call(
		uintptr(unsafe.Pointer(time)),
		uintptr(unsafe.Pointer(&sysTime)),
	)

	return ret != 0, &sysTime
}

// WaitForSingleObject wait duration
const (
	WAIT_DONT_WAIT       = 0
	WAIT_ONE_MILLISECOND = 1
	WAIT_ONE_SECOND      = 1000
	WAIT_INFINITE        = 0xFFFFFFFF
)

// WaitForSingleObject return codes
const (
	WAIT_SIGNALED  = 0x00000000
	WAIT_ABANDONED = 0x00000080
	WAIT_TIMEOUT   = 0x00000102
	WAIT_FAILED    = 0xFFFFFFFF
)

// WaitForSingleObject waits for the object to be signaled.
// Returns true if the object was signaled, false otherwise.
// It returns an error when the wait fails for a reason other than the object not being signaled.
func WaitForSingleObject(object HANDLE, msWait uint32) uint32 {
	switch res, _, _ := procWaitForSingleObject.Call(uintptr(object), uintptr(msWait)); res {
	case WAIT_SIGNALED, WAIT_ABANDONED, WAIT_TIMEOUT:
		return uint32(res)
	default:
		return WAIT_FAILED
	}
}
