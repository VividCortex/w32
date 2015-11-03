// Copyright 2010-2012 The W32 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package w32

/*
#include <windows.h>

typedef struct _MIB_TCPROW {
  DWORD     dwState;
  DWORD     dwLocalAddr;
  DWORD     dwLocalPort;
  DWORD     dwRemoteAddr;
  DWORD     dwRemotePort;
} MIB_TCPROW, *PMIB_TCPROW;

typedef struct _MIB_TCPTABLE {
  DWORD     dwNumEntries;
  //MIB_TCPROW table[];
} MIB_TCPTABLE, *PMIB_TCPTABLE;

typedef struct _MIB_TCPROW2 {
  DWORD     dwState;
  DWORD     dwLocalAddr;
  DWORD     dwLocalPort;
  DWORD     dwRemoteAddr;
  DWORD     dwRemotePort;
  DWORD     dwOwningPid;
  DWORD     dwOffloadState;
} MIB_TCPROW2, *PMIB_TCPROW2;

typedef struct _MIB_TCPTABLE2 {
  DWORD     dwNumEntries;
  //MIB_TCPROW2 table[];
} MIB_TCPTABLE2, *PMIB_TCPTABLE2;

typedef struct _MIB_TCP6ROW {
  int       State;
  byte      LocalAddr[16];
  DWORD     dwLocalScopeId;
  DWORD     dwLocalPort;
  byte      RemoteAddr[16];
  DWORD     dwRemoteScopeId;
  DWORD     dwRemotePort;
} MIB_TCP6ROW, *PMIB_TCP6ROW;

typedef struct _MIB_TCP6TABLE {
  DWORD     dwNumEntries;
  //MIB_TCP6ROW table[];
} MIB_TCP6TABLE, *PMIB_TCP6TABLE;

typedef struct _MIB_TCP6ROW2 {
  byte      LocalAddr[16];
  DWORD     dwLocalScopeId;
  DWORD     dwLocalPort;
  byte      RemoteAddr[16];
  DWORD     dwRemoteScopeId;
  DWORD     dwRemotePort;
  DWORD     State;
  DWORD     dwOwningPid;
  DWORD     dwOffloadState;
} MIB_TCP6ROW2, *PMIB_TCP6ROW2;

typedef struct _MIB_TCP6TABLE2 {
  DWORD     dwNumEntries;
  //MIB_TCP6ROW2 table[];
} MIB_TCP6TABLE2, *PMIB_TCP6TABLE2;

MIB_TCP6TABLE* GetTcp6TableBuffer(DWORD buffersize){
  MIB_TCP6TABLE *pTable = NULL;
  pTable = (MIB_TCP6TABLE *) malloc(buffersize);
  return pTable;
}

MIB_TCP6TABLE2* GetTcp6Table2Buffer(DWORD buffersize){
  MIB_TCP6TABLE2 *pTable = NULL;
  pTable = (MIB_TCP6TABLE2 *) malloc(buffersize);
  return pTable;
}

MIB_TCPTABLE* GetTcpTableBuffer(DWORD buffersize){
  MIB_TCPTABLE *pTable = NULL;
  pTable = (MIB_TCPTABLE *) malloc(buffersize);
  return pTable;
}

MIB_TCPTABLE2* GetTcpTable2Buffer(DWORD buffersize){
  MIB_TCPTABLE2 *pTable = NULL;
  pTable = (MIB_TCPTABLE2 *) malloc(buffersize);
  return pTable;
}
*/
import "C"

import (
	"reflect"
	"syscall"
	"unsafe"
)

var (
	modiphlpapi = syscall.NewLazyDLL("Iphlpapi.dll")

	procGetIpStatisticsEx  = modiphlpapi.NewProc("GetIpStatisticsEx")
	procGetTcpStatisticsEx = modiphlpapi.NewProc("GetTcpStatisticsEx")
	procGetTcpTable        = modiphlpapi.NewProc("GetTcpTable")
	procGetTcpTable2       = modiphlpapi.NewProc("GetTcpTable2")
	procGetTcp6Table       = modiphlpapi.NewProc("GetTcp6Table")
	procGetTcp6Table2      = modiphlpapi.NewProc("GetTcp6Table2")
)

const (
	ERROR_INSUFFICIENT_BUFFER = 122
	ERROR_INVALID_PARAMETER   = 87
	ERROR_NOT_SUPPORTED       = 50
)

func GetIpStatisticsEx(ipv6 bool) (MIB_IPSTATS, bool) {
	ipFamily := 2 // AF_INET
	if ipv6 {
		ipFamily = 23 // AF_INET6
	}
	stats := MIB_IPSTATS{}
	ret, _, _ := procGetIpStatisticsEx.Call(
		uintptr(unsafe.Pointer(&stats)),
		uintptr(ipFamily),
	)

	return stats, ret == 0
}

type MIB_IPSTATS struct {
	Forwarding      uint32
	DefaultTTL      uint32
	InReceives      uint32
	InHdrErrors     uint32
	InAddrErrors    uint32
	ForwDatagrams   uint32
	InUnknownProtos uint32
	InDiscards      uint32
	InDelivers      uint32
	OutRequests     uint32
	RoutingDiscards uint32
	OutDiscards     uint32
	OutNoRoutes     uint32
	ReasmTimeout    uint32
	ReasmReqds      uint32
	ReasmOks        uint32
	ReasmFails      uint32
	FragOks         uint32
	FragFails       uint32
	FragCreates     uint32
	NumIf           uint32
	NumAddr         uint32
	NumRoutes       uint32
}

func GetTcpStatisticsEx(ipv6 bool) (MIB_TCPSTATS, bool) {
	ipFamily := 2 // AF_INET
	if ipv6 {
		ipFamily = 23 // AF_INET6
	}
	stats := MIB_TCPSTATS{}
	ret, _, _ := procGetTcpStatisticsEx.Call(
		uintptr(unsafe.Pointer(&stats)),
		uintptr(ipFamily),
	)

	return stats, ret == 0
}

// https://msdn.microsoft.com/en-us/library/aa366915(v=vs.85).aspx
type MIB_TCPSTATS struct {
	RtoAlgorithm uint32
	RtoMin       uint32
	RtoMax       uint32
	MaxConn      uint32
	ActiveOpens  uint32
	PassiveOpens uint32
	AttemptFails uint32
	EstabResets  uint32
	CurrEstab    uint32
	InSegs       uint32
	OutSegs      uint32
	RetransSegs  uint32
	InErrs       uint32
	OutRsts      uint32
	NumConns     uint32
}

func GetTcpTable(sortResults bool) (table MIB_TCPTABLE, status uint32) {
	sort := FALSE
	if sortResults {
		sort = TRUE
	}

	bufSize := uint32(0)
	ret, _, _ := procGetTcpTable.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(&bufSize)),
		uintptr(sort),
	)

	if status = uint32(ret); status != ERROR_INSUFFICIENT_BUFFER {
		return
	}

	// Allocate our table with a buffer for a few extra rows, just in case
	tableBuf := C.GetTcpTableBuffer(C.DWORD(bufSize + tcp4RowSize*20))
	unsafeTableBuf := unsafe.Pointer(tableBuf)
	defer C.free(unsafeTableBuf)

	ret, _, _ = procGetTcpTable.Call(
		uintptr(unsafeTableBuf),
		uintptr(unsafe.Pointer(&bufSize)),
		uintptr(sort),
	)

	if status = uint32(ret); status != NO_ERROR {
		return
	}

	table.NumEntries = uint32(tableBuf.dwNumEntries)
	table.Table = make([]MIB_TCPROW, table.NumEntries)

	buf := *(*[]C.MIB_TCPROW)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(uintptr(unsafeTableBuf) + C.sizeof_struct__MIB_TCPTABLE)),
		Len:  int(table.NumEntries),
		Cap:  int(table.NumEntries),
	}))

	for i := 0; i < int(table.NumEntries); i++ {
		table.Table[i] = MIB_TCPROW{
			State:      uint32(buf[i].dwState),
			LocalAddr:  uint32(buf[i].dwLocalAddr),
			LocalPort:  uint16(buf[i].dwLocalPort)<<8 | uint16(buf[i].dwLocalPort)>>8,
			RemoteAddr: uint32(buf[i].dwRemoteAddr),
			RemotePort: uint16(buf[i].dwRemotePort)<<8 | uint16(buf[i].dwRemotePort)>>8,
		}
	}

	return
}

// https://msdn.microsoft.com/en-us/library/aa366917(v=vs.85).aspx
type MIB_TCPTABLE struct {
	NumEntries uint32
	Table      []MIB_TCPROW
}

// https://msdn.microsoft.com/en-us/library/aa366909(v=vs.85).aspx
type MIB_TCPROW struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint16
	RemoteAddr uint32
	RemotePort uint16
}

var tcp4RowSize = uint32(unsafe.Sizeof(MIB_TCPROW{}))

func GetTcpTable2(sortResults bool) (table MIB_TCPTABLE2, status uint32) {
	sort := FALSE
	if sortResults {
		sort = TRUE
	}

	bufSize := uint32(0)
	ret, _, _ := procGetTcpTable2.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(&bufSize)),
		uintptr(sort),
	)

	if status = uint32(ret); status != ERROR_INSUFFICIENT_BUFFER {
		return
	}

	// Allocate our table with a buffer for a few extra rows, just in case
	tableBuf := C.GetTcpTableBuffer(C.DWORD(bufSize + tcp4Row2Size*20))
	unsafeTableBuf := unsafe.Pointer(tableBuf)
	defer C.free(unsafeTableBuf)

	ret, _, _ = procGetTcpTable2.Call(
		uintptr(unsafeTableBuf),
		uintptr(unsafe.Pointer(&bufSize)),
		uintptr(sort),
	)

	if status = uint32(ret); status != NO_ERROR {
		return
	}

	table.NumEntries = uint32(tableBuf.dwNumEntries)
	table.Table = make([]MIB_TCPROW2, table.NumEntries)

	buf := *(*[]C.MIB_TCPROW2)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(uintptr(unsafeTableBuf) + C.sizeof_struct__MIB_TCPTABLE2)),
		Len:  int(table.NumEntries),
		Cap:  int(table.NumEntries),
	}))

	for i := 0; i < int(table.NumEntries); i++ {
		table.Table[i] = MIB_TCPROW2{
			State:        uint32(buf[i].dwState),
			LocalAddr:    uint32(buf[i].dwLocalAddr),
			LocalPort:    uint16(buf[i].dwLocalPort)<<8 | uint16(buf[i].dwLocalPort)>>8,
			RemoteAddr:   uint32(buf[i].dwRemoteAddr),
			RemotePort:   uint16(buf[i].dwRemotePort)<<8 | uint16(buf[i].dwRemotePort)>>8,
			Pid:          uint32(buf[i].dwOwningPid),
			OffloadState: TCP_CONNECTION_OFFLOAD_STATE(buf[i].dwOffloadState),
		}
	}

	return
}

// https://msdn.microsoft.com/en-us/library/bb485772(v=vs.85).aspx
type MIB_TCPTABLE2 struct {
	NumEntries uint32
	Table      []MIB_TCPROW2
}

// https://msdn.microsoft.com/en-us/library/bb485761(v=vs.85).aspx
type MIB_TCPROW2 struct {
	State        uint32
	LocalAddr    uint32
	LocalPort    uint16
	RemoteAddr   uint32
	RemotePort   uint16
	Pid          uint32
	OffloadState TCP_CONNECTION_OFFLOAD_STATE
}

var tcp4Row2Size = uint32(unsafe.Sizeof(MIB_TCPROW2{}))

func GetTcp6Table(sortResults bool) (table MIB_TCP6TABLE, status uint32) {
	sort := FALSE
	if sortResults {
		sort = TRUE
	}

	bufSize := uint32(0)
	ret, _, _ := procGetTcp6Table.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(&bufSize)),
		uintptr(sort),
	)

	if status = uint32(ret); status != ERROR_INSUFFICIENT_BUFFER {
		return
	}

	// Allocate our table with a buffer for a few extra rows, just in case
	tableBuf := C.GetTcp6TableBuffer(C.DWORD(bufSize + tcp6RowSize*20))
	unsafeTableBuf := unsafe.Pointer(tableBuf)
	defer C.free(unsafeTableBuf)

	ret, _, _ = procGetTcp6Table.Call(
		uintptr(unsafeTableBuf),
		uintptr(unsafe.Pointer(&bufSize)),
		uintptr(sort),
	)

	if status = uint32(ret); status != NO_ERROR {
		return
	}

	table.NumEntries = uint32(tableBuf.dwNumEntries)
	table.Table = make([]MIB_TCP6ROW, table.NumEntries)

	buf := *(*[]C.MIB_TCP6ROW)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(uintptr(unsafeTableBuf) + C.sizeof_struct__MIB_TCP6TABLE)),
		Len:  int(table.NumEntries),
		Cap:  int(table.NumEntries),
	}))

	for i := 0; i < int(table.NumEntries); i++ {
		table.Table[i] = MIB_TCP6ROW{
			State:         MIB_TCP_STATE(buf[i].State),
			LocalAddr:     []byte(C.GoBytes(unsafe.Pointer(&buf[i].LocalAddr), 16)),
			LocalScopeId:  uint32(buf[i].dwLocalScopeId),
			LocalPort:     uint16(buf[i].dwLocalPort)<<8 | uint16(buf[i].dwLocalPort)>>8,
			RemoteAddr:    []byte(C.GoBytes(unsafe.Pointer(&buf[i].RemoteAddr), 16)),
			RemoteScopeId: uint32(buf[i].dwRemoteScopeId),
			RemotePort:    uint16(buf[i].dwRemotePort)<<8 | uint16(buf[i].dwRemotePort)>>8,
		}
	}

	return
}

// https://msdn.microsoft.com/en-us/library/aa814506(v=vs.85).aspx
type MIB_TCP6TABLE struct {
	NumEntries uint32
	Table      []MIB_TCP6ROW
}

// https://msdn.microsoft.com/en-us/library/aa814505(v=vs.85).aspx
type MIB_TCP6ROW struct {
	State         MIB_TCP_STATE
	LocalAddr     []byte
	LocalScopeId  uint32
	LocalPort     uint16
	RemoteAddr    []byte
	RemoteScopeId uint32
	RemotePort    uint16
}

var tcp6RowSize = uint32(unsafe.Sizeof(MIB_TCP6ROW{}))

func GetTcp6Table2(sortResults bool) (table MIB_TCP6TABLE2, status uint32) {
	sort := FALSE
	if sortResults {
		sort = TRUE
	}

	bufSize := uint32(0)
	ret, _, _ := procGetTcp6Table2.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(&bufSize)),
		uintptr(sort),
	)

	if status = uint32(ret); status != ERROR_INSUFFICIENT_BUFFER {
		return
	}

	// Allocate our table with a buffer for a few extra rows, just in case
	tableBuf := C.GetTcp6Table2Buffer(C.DWORD(bufSize + tcp6Row2Size*20))
	unsafeTableBuf := unsafe.Pointer(tableBuf)
	defer C.free(unsafeTableBuf)

	ret, _, _ = procGetTcp6Table2.Call(
		uintptr(unsafeTableBuf),
		uintptr(unsafe.Pointer(&bufSize)),
		uintptr(sort),
	)

	if status = uint32(ret); status != NO_ERROR {
		return
	}

	table.NumEntries = uint32(tableBuf.dwNumEntries)
	table.Table = make([]MIB_TCP6ROW2, table.NumEntries)

	buf := *(*[]C.MIB_TCP6ROW2)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(uintptr(unsafeTableBuf) + C.sizeof_struct__MIB_TCP6TABLE2)),
		Len:  int(table.NumEntries),
		Cap:  int(table.NumEntries),
	}))

	for i := 0; i < int(table.NumEntries); i++ {
		table.Table[i] = MIB_TCP6ROW2{
			LocalAddr:     []byte(C.GoBytes(unsafe.Pointer(&buf[i].LocalAddr), 16)),
			LocalScopeId:  uint32(buf[i].dwLocalScopeId),
			LocalPort:     uint16(buf[i].dwLocalPort)<<8 | uint16(buf[i].dwLocalPort)>>8,
			RemoteAddr:    []byte(C.GoBytes(unsafe.Pointer(&buf[i].RemoteAddr), 16)),
			RemoteScopeId: uint32(buf[i].dwRemoteScopeId),
			RemotePort:    uint16(buf[i].dwRemotePort)<<8 | uint16(buf[i].dwRemotePort)>>8,
			State:         MIB_TCP_STATE(buf[i].State),
			Pid:           uint32(buf[i].dwOwningPid),
			OffloadState:  TCP_CONNECTION_OFFLOAD_STATE(buf[i].dwOffloadState),
		}
	}

	return
}

// https://msdn.microsoft.com/en-us/library/bb485749(v=vs.85).aspx
type MIB_TCP6TABLE2 struct {
	NumEntries uint32
	Table      []MIB_TCP6ROW2
}

// https://msdn.microsoft.com/en-us/library/bb485739(v=vs.85).aspx
type MIB_TCP6ROW2 struct {
	LocalAddr     []byte
	LocalScopeId  uint32
	LocalPort     uint16
	RemoteAddr    []byte
	RemoteScopeId uint32
	RemotePort    uint16
	State         MIB_TCP_STATE
	Pid           uint32
	OffloadState  TCP_CONNECTION_OFFLOAD_STATE
}

var tcp6Row2Size = uint32(unsafe.Sizeof(MIB_TCP6ROW2{}))

type MIB_TCP_STATE uint32

const (
	MIB_TCP_STATE_CLOSED     = 1
	MIB_TCP_STATE_LISTEN     = 2
	MIB_TCP_STATE_SYN_SENT   = 3
	MIB_TCP_STATE_SYN_RCVD   = 4
	MIB_TCP_STATE_ESTAB      = 5
	MIB_TCP_STATE_FIN_WAIT1  = 6
	MIB_TCP_STATE_FIN_WAIT2  = 7
	MIB_TCP_STATE_CLOSE_WAIT = 8
	MIB_TCP_STATE_CLOSING    = 9
	MIB_TCP_STATE_LAST_ACK   = 10
	MIB_TCP_STATE_TIME_WAIT  = 11
	MIB_TCP_STATE_DELETE_TCB = 12
)

type TCP_CONNECTION_OFFLOAD_STATE uint32

const (
	TCP_OFFLOAD_STATE_INHOST     = 0
	TCP_OFFLOAD_STATE_OFFLOADING = 1
	TCP_OFFLOAD_STATE_OFFLOADED  = 2
	TCP_OFFLOAD_STATE_UPLOADING  = 3
	TCP_OFFLOAD_STATE_MAX        = 4
)
