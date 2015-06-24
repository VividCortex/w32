// Copyright 2010-2012 The W32 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package w32

/*
#include <windows.h>

typedef struct _PDH_FMT_COUNTERVALUE {
  DWORD  CStatus;
  double doubleValue;
} PDH_FMT_COUNTERVALUE, *PPDH_FMT_COUNTERVALUE;

typedef struct _PDH_FMT_COUNTERVALUE_ITEM {
  LPTSTR               szName;
  PDH_FMT_COUNTERVALUE FmtValue;
} PDH_FMT_COUNTERVALUE_ITEM, *PPDH_FMT_COUNTERVALUE_ITEM;

PDH_FMT_COUNTERVALUE_ITEM* getCounterValueBuffer(DWORD buffersize){
	 PDH_FMT_COUNTERVALUE_ITEM *pItems = NULL;
	 pItems = (PDH_FMT_COUNTERVALUE_ITEM *) malloc(buffersize);

	return pItems;
}
*/
import "C"

import (
	"fmt"
	"reflect"
	"syscall"
	"unsafe"
)

const (
	PDH_SUCCESS = 0x00
	// Status codes returned from PDH functions
	PDH_MORE_DATA                 = 0x800007D2
	PDH_CSTATUS_BAD_COUNTERNAME   = 0xC0000BC0
	PDH_CSTATUS_NO_COUNTER        = 0xC0000BB9
	PDH_CSTATUS_NO_COUNTERNAME    = 0xC0000BBF
	PDH_CSTATUS_NO_INSTANCE       = 0x800007D1
	PDH_CSTATUS_NO_MACHINE        = 0x800007D0
	PDH_CSTATUS_NO_OBJECT         = 0xC0000BB8
	PDH_FUNCTION_NOT_FOUND        = 0xC0000BBE
	PDH_INVALID_ARGUMENT          = 0xC0000BBD
	PDH_INVALID_HANDLE            = 0xC0000BBC
	PDH_MEMORY_ALLOCATION_FAILURE = 0xC0000BBB

	// Argument options
	PERF_DETAIL_NOVICE   = 100
	PERF_DETAIL_ADVANCED = 200
	PERF_DETAIL_EXPERT   = 300
	PERF_DETAIL_WIZARD   = 400

	// Counter Formats options
	PDH_FMT_LONG   = 0x00000100 // long integer
	PDH_FMT_DOUBLE = 0x00000200 // double precision float
	PDH_FMT_LARGE  = 0x00000400 // 64-bit integer

	PDH_FMT_NOSCALE = 0x00001000 // Do not apply the counter's default scaling factor.
	PDH_FMT_1000    = 0x00002000 // Multiply the actual value by 1,000.

	/* Counter values greater than 100 (for example,
	   counter values measuring the processor load on multiprocessor computers)
	   will not be reset to 100. The default behavior is that
	   counter values are capped at a value of 100. */
	PDH_FMT_NOCAP100 = 0x00008000
)

var (
	modpdh = syscall.NewLazyDLL("pdh.dll")

	procPdhEnumObjects              = modpdh.NewProc("PdhEnumObjectsA")
	procPdhEnumObjectItems          = modpdh.NewProc("PdhEnumObjectItemsA")
	procPdhOpenQuery                = modpdh.NewProc("PdhOpenQueryA")
	procPdhAddCounter               = modpdh.NewProc("PdhAddCounterA")
	procPdhCollectQueryData         = modpdh.NewProc("PdhCollectQueryData")
	procPdhValidatePath             = modpdh.NewProc("PdhValidatePathA")
	procPdhGetFormattedCounterValue = modpdh.NewProc("PdhGetFormattedCounterValue")
	procPdhGetFormattedCounterArray = modpdh.NewProc("PdhGetFormattedCounterArrayA")
)

type PDH_ERROR struct {
	Code        uint32
	Description string
}

func (err *PDH_ERROR) Error() string {
	return err.Description
}

func (err *PDH_ERROR) String() string {
	return err.Description
}

func PdhErrorCode(sCode uint32) *PDH_ERROR {
	switch sCode {
	case 0:
		return nil
	case PDH_MORE_DATA:
		return &PDH_ERROR{Code: sCode,
			Description: "There is more data to return than would fit in the supplied buffer. Allocate a larger buffer and call the function again."}
	case PDH_CSTATUS_BAD_COUNTERNAME:
		return &PDH_ERROR{Code: sCode,
			Description: "Unable to parse the counter path. Check the format and syntax of the specified path."}
	case PDH_CSTATUS_NO_COUNTER:
		return &PDH_ERROR{Code: sCode,
			Description: "The specified counter could not be found."}
	case PDH_CSTATUS_NO_COUNTERNAME:
		return &PDH_ERROR{Code: sCode,
			Description: "No counter was specified."}
	case PDH_CSTATUS_NO_INSTANCE:
		return &PDH_ERROR{Code: sCode,
			Description: "The specified instance is not present."}
	case PDH_CSTATUS_NO_MACHINE:
		return &PDH_ERROR{Code: sCode,
			Description: "Unable to connect to the specified computer, or the computer is offline."}
	case PDH_CSTATUS_NO_OBJECT:
		return &PDH_ERROR{Code: sCode,
			Description: "The specified object is not found on the system."}
	case PDH_FUNCTION_NOT_FOUND:
		return &PDH_ERROR{Code: sCode,
			Description: "Unable to find the specified function."}
	case PDH_INVALID_ARGUMENT:
		return &PDH_ERROR{Code: sCode,
			Description: "A required argument is missing or incorrect."}
	case PDH_INVALID_HANDLE:
		return &PDH_ERROR{Code: sCode,
			Description: "The handle is not a valid PDH object."}
	case PDH_MEMORY_ALLOCATION_FAILURE:
		return &PDH_ERROR{Code: sCode,
			Description: "A PDH function could not allocate enough temporary memory to complete the operation. Close some applications or extend the page file and retry the function."}
	default:
		return &PDH_ERROR{Code: sCode, Description: fmt.Sprintf("Unimplemented error, code 0x%X", sCode)}
	}
}

func PdhEnumObjects(detailLevel uint32, refreshCache bool, bufferlen uint32) (uint32, []byte, uint32) {
	var buf []byte
	var buflen uint32
	var bufPtr *byte
	if bufferlen > 0 {
		buf = make([]byte, bufferlen+1)
		bufPtr = &buf[0]
		buf[bufferlen] = 0
		buflen = uint32(bufferlen)
	}

	refreshCacheWin := TRUE
	if !refreshCache {
		refreshCacheWin = FALSE
	}

	ret, _, _ := procPdhEnumObjects.Call(
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(bufPtr)),
		uintptr(unsafe.Pointer(&buflen)),
		uintptr(detailLevel),
		uintptr(refreshCacheWin),
	)

	if buflen > 0 && uint32(ret) == 0 {
		return uint32(ret), buf[:buflen-1], buflen
	}
	return uint32(ret), []byte{}, buflen
}

func PdhEnumObjectItems(object string, counterBufferLen, instanceBufferLen uint32,
	detailLevel uint32) (status uint32, outCountBuf []byte, outCountLen uint32,
	outInstBuf []byte, outInstLen uint32) {
	var counterBuf []byte
	var counterBufLen uint32
	var counterBufPtr *byte
	if counterBufferLen > 0 {
		counterBuf = make([]byte, counterBufferLen+1)
		counterBufPtr = &counterBuf[0]
		counterBuf[counterBufferLen] = 0
		counterBufLen = uint32(counterBufferLen)
	}

	var instanceBuf []byte
	var instanceBufLen uint32
	var instanceBufPtr *byte
	if instanceBufferLen > 0 {
		instanceBuf = make([]byte, instanceBufferLen+1)
		instanceBufPtr = &instanceBuf[0]
		instanceBuf[instanceBufferLen] = 0
		instanceBufLen = uint32(instanceBufferLen)
	}

	objName, _ := syscall.BytePtrFromString(object)
	ret, _, _ := procPdhEnumObjectItems.Call(
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(objName)),
		uintptr(unsafe.Pointer(counterBufPtr)),
		uintptr(unsafe.Pointer(&counterBufLen)),
		uintptr(unsafe.Pointer(instanceBufPtr)),
		uintptr(unsafe.Pointer(&instanceBufLen)),
		uintptr(detailLevel),
		uintptr(uint32(0)),
	)

	if uint32(ret) != 0 {
		return uint32(ret), []byte{}, counterBufLen, []byte{}, instanceBufLen
	}
	if counterBufLen > 0 {
		outCountBuf = counterBuf[:counterBufLen-1]
		outCountLen = counterBufLen
	}
	if instanceBufLen > 0 {
		outInstBuf = instanceBuf[:instanceBufLen-1]
		outInstLen = instanceBufLen
	}

	return uint32(ret), outCountBuf, outCountLen, outInstBuf, outInstLen
}

func PdhOpenQuery() (uint32, HANDLE) {
	var pdhQuery HANDLE
	var userData uintptr
	ret, _, _ := procPdhOpenQuery.Call(
		uintptr(0),
		uintptr(userData),
		uintptr(unsafe.Pointer(&pdhQuery)),
	)

	return uint32(ret), pdhQuery
}

func PdhAddCounter(pdhQuery HANDLE, counterPath string) (uint32, HANDLE) {
	var counter HANDLE
	var userData uintptr

	path, _ := syscall.BytePtrFromString(counterPath)

	ret, _, _ := procPdhAddCounter.Call(
		uintptr(pdhQuery),
		uintptr(unsafe.Pointer(path)),
		uintptr(userData),
		uintptr(unsafe.Pointer(&counter)),
	)

	return uint32(ret), counter
}

func PdhCollectQueryData(pdhQuery HANDLE) (uint32, HANDLE) {
	ret, _, _ := procPdhCollectQueryData.Call(
		uintptr(pdhQuery),
	)

	return uint32(ret), pdhQuery
}

func PdhGetFormattedCounterValue(hCounter HANDLE) (status uint32, outBuffer PDH_FMT_COUNTERVALUE) {
	counterType := uint32(0)
	var buffer C.PDH_FMT_COUNTERVALUE
	ret, _, _ := procPdhGetFormattedCounterValue.Call(
		uintptr(hCounter),
		uintptr(uint32(PDH_FMT_DOUBLE|PDH_FMT_NOSCALE)),
		uintptr(unsafe.Pointer(&counterType)),
		uintptr(unsafe.Pointer(&buffer)),
	)

	if status = uint32(ret); status != 0 {
		return
	}

	outBuffer = PDH_FMT_COUNTERVALUE{
		Status: uint32(buffer.CStatus),
		Value:  float64(buffer.doubleValue),
	}

	return
}

func PdhGetFormattedCounterArray(hCounter HANDLE) (status uint32,
	respLen uint32, numItems uint32, outBuffer []PDH_FMT_COUNTERVALUE_ITEM) {

	// Call once to get buffer size
	ret, _, _ := procPdhGetFormattedCounterArray.Call(
		uintptr(hCounter),
		uintptr(uint32(PDH_FMT_DOUBLE|PDH_FMT_NOSCALE)),
		uintptr(unsafe.Pointer(&respLen)),
		uintptr(unsafe.Pointer(&numItems)),
		uintptr(0),
	)

	if status = uint32(ret); status != PDH_MORE_DATA {
		return
	}

	itemBuffer := C.getCounterValueBuffer(C.DWORD(respLen))
	defer C.free(unsafe.Pointer(itemBuffer))

	ret, _, _ = procPdhGetFormattedCounterArray.Call(
		uintptr(hCounter),
		uintptr(uint32(PDH_FMT_DOUBLE|PDH_FMT_NOSCALE)),
		uintptr(unsafe.Pointer(&respLen)),
		uintptr(unsafe.Pointer(&numItems)),
		uintptr(unsafe.Pointer(itemBuffer)),
	)

	if status = uint32(ret); status != 0 {
		return
	}

	bufferArray := *(*[]C.PDH_FMT_COUNTERVALUE_ITEM)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(itemBuffer)),
		Len:  int(numItems),
		Cap:  int(numItems),
	}))

	outBuffer = make([]PDH_FMT_COUNTERVALUE_ITEM, numItems)
	// Loop through the array and print the instance name and counter value.
	for i := uint32(0); i < numItems; i++ {
		outBuffer[i].Name = C.GoString((*C.char)(unsafe.Pointer(bufferArray[i].szName)))
		outBuffer[i].Item = PDH_FMT_COUNTERVALUE{
			Status: uint32(bufferArray[i].FmtValue.CStatus),
			Value:  float64(bufferArray[i].FmtValue.doubleValue),
		}
	}

	return
}

func PdhValidatePath(processCounterPath string) uint32 {
	path, _ := syscall.BytePtrFromString(processCounterPath)

	ret, _, _ := procPdhValidatePath.Call(
		uintptr(unsafe.Pointer(path)),
	)

	return uint32(ret)
}
