// Copyright 2010-2012 The W32 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package w32

/*
#include <windows.h>

typedef struct _X_LUID_AND_ATTRIBUTES {
  DWORD               LuidLow;
  DWORD               LuidHigh;
  DWORD               Attributes;
} X_LUID_AND_ATTRIBUTES;

typedef struct _X_TOKEN_PRIVILEGES {
  DWORD               PrivilegeCount;
  //X_LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
} X_TOKEN_PRIVILEGES;
*/
import "C"

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procRegCreateKeyEx = modadvapi32.NewProc("RegCreateKeyExW")
	procRegOpenKeyEx   = modadvapi32.NewProc("RegOpenKeyExW")
	procRegCloseKey    = modadvapi32.NewProc("RegCloseKey")
	procRegGetValue    = modadvapi32.NewProc("RegGetValueW")
	procRegEnumKeyEx   = modadvapi32.NewProc("RegEnumKeyExW")
	//	procRegSetKeyValue     = modadvapi32.NewProc("RegSetKeyValueW")
	procRegSetValueEx         = modadvapi32.NewProc("RegSetValueExW")
	procRegDeleteKeyValue     = modadvapi32.NewProc("RegDeleteKeyValueW")
	procRegDeleteValue        = modadvapi32.NewProc("RegDeleteValueW")
	procRegDeleteTree         = modadvapi32.NewProc("RegDeleteTreeW")
	procOpenEventLog          = modadvapi32.NewProc("OpenEventLogW")
	procReadEventLog          = modadvapi32.NewProc("ReadEventLogW")
	procCloseEventLog         = modadvapi32.NewProc("CloseEventLog")
	procOpenSCManager         = modadvapi32.NewProc("OpenSCManagerW")
	procCloseServiceHandle    = modadvapi32.NewProc("CloseServiceHandle")
	procOpenService           = modadvapi32.NewProc("OpenServiceW")
	procStartService          = modadvapi32.NewProc("StartServiceW")
	procControlService        = modadvapi32.NewProc("ControlService")
	procOpenProcessToken      = modadvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValue  = modadvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = modadvapi32.NewProc("AdjustTokenPrivileges")
	procGetTokenInformation   = modadvapi32.NewProc("GetTokenInformation")
	procCreateWellKnownSid    = modadvapi32.NewProc("CreateWellKnownSid")
	procCheckTokenMembership  = modadvapi32.NewProc("CheckTokenMembership")
)

func RegCreateKey(hKey HKEY, subKey string) HKEY {
	var result HKEY
	ret, _, _ := procRegCreateKeyEx.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(KEY_ALL_ACCESS),
		uintptr(0),
		uintptr(unsafe.Pointer(&result)),
		uintptr(0))
	_ = ret
	return result
}

func RegOpenKeyEx(hKey HKEY, subKey string, samDesired uint32) HKEY {
	var result HKEY
	ret, _, _ := procRegOpenKeyEx.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(0),
		uintptr(samDesired),
		uintptr(unsafe.Pointer(&result)))

	if ret != ERROR_SUCCESS {
		panic(fmt.Sprintf("RegOpenKeyEx(%d, %s, %d) failed", hKey, subKey, samDesired))
	}
	return result
}

func RegCloseKey(hKey HKEY) error {
	var err error
	ret, _, _ := procRegCloseKey.Call(
		uintptr(hKey))

	if ret != ERROR_SUCCESS {
		err = errors.New("RegCloseKey failed")
	}
	return err
}

func RegGetRaw(hKey HKEY, subKey string, value string) []byte {
	var bufLen uint32
	var valptr unsafe.Pointer
	if len(value) > 0 {
		valptr = unsafe.Pointer(syscall.StringToUTF16Ptr(value))
	}
	procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(valptr),
		uintptr(RRF_RT_ANY),
		0,
		0,
		uintptr(unsafe.Pointer(&bufLen)))

	if bufLen == 0 {
		return nil
	}

	buf := make([]byte, bufLen)
	ret, _, _ := procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(valptr),
		uintptr(RRF_RT_ANY),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufLen)))

	if ret != ERROR_SUCCESS {
		return nil
	}

	return buf
}

func RegSetBinary(hKey HKEY, subKey string, value []byte) (errno int) {
	var lptr, vptr unsafe.Pointer
	if len(subKey) > 0 {
		lptr = unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))
	}
	if len(value) > 0 {
		vptr = unsafe.Pointer(&value[0])
	}
	ret, _, _ := procRegSetValueEx.Call(
		uintptr(hKey),
		uintptr(lptr),
		uintptr(0),
		uintptr(REG_BINARY),
		uintptr(vptr),
		uintptr(len(value)))

	return int(ret)
}

func RegSetString(hKey HKEY, subKey string, value string) (errno int) {
	var lptr, vptr unsafe.Pointer
	if len(subKey) > 0 {
		lptr = unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))
	}
	var buf []uint16
	if len(value) > 0 {
		buf, err := syscall.UTF16FromString(value)
		if err != nil {
			return ERROR_BAD_FORMAT
		}
		vptr = unsafe.Pointer(&buf[0])
	}
	ret, _, _ := procRegSetValueEx.Call(
		uintptr(hKey),
		uintptr(lptr),
		uintptr(0),
		uintptr(REG_SZ),
		uintptr(vptr),
		uintptr(unsafe.Sizeof(buf)+2)) // 2 is the size of the terminating null character

	return int(ret)
}

func RegSetUint32(hKey HKEY, subKey string, value uint32) (errno int) {
	var lptr unsafe.Pointer
	if len(subKey) > 0 {
		lptr = unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))
	}
	vptr := unsafe.Pointer(&value)
	ret, _, _ := procRegSetValueEx.Call(
		uintptr(hKey),
		uintptr(lptr),
		uintptr(0),
		uintptr(REG_DWORD),
		uintptr(vptr),
		uintptr(unsafe.Sizeof(value)))

	return int(ret)
}

func RegGetString(hKey HKEY, subKey string, value string) string {
	var bufLen uint32
	procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(value))),
		uintptr(RRF_RT_REG_SZ),
		0,
		0,
		uintptr(unsafe.Pointer(&bufLen)))

	if bufLen == 0 {
		return ""
	}

	buf := make([]uint16, bufLen)
	ret, _, _ := procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(value))),
		uintptr(RRF_RT_REG_SZ),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufLen)))

	if ret != ERROR_SUCCESS {
		return ""
	}

	return syscall.UTF16ToString(buf)
}

func RegGetUint32(hKey HKEY, subKey string, value string) (data uint32, errno int) {
	var dataLen uint32 = uint32(unsafe.Sizeof(data))
	ret, _, _ := procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(value))),
		uintptr(RRF_RT_REG_DWORD),
		0,
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&dataLen)))
	errno = int(ret)
	return
}

/*
func RegSetKeyValue(hKey HKEY, subKey string, valueName string, dwType uint32, data uintptr, cbData uint16) (errno int) {
	ret, _, _ := procRegSetKeyValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(valueName))),
		uintptr(dwType),
		data,
		uintptr(cbData))

	return int(ret)
}
*/

func RegDeleteKeyValue(hKey HKEY, subKey string, valueName string) (errno int) {
	ret, _, _ := procRegDeleteKeyValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(valueName))))

	return int(ret)
}

func RegDeleteValue(hKey HKEY, valueName string) (errno int) {
	ret, _, _ := procRegDeleteValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(valueName))))

	return int(ret)
}

func RegDeleteTree(hKey HKEY, subKey string) (errno int) {
	ret, _, _ := procRegDeleteTree.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))))

	return int(ret)
}

func RegEnumKeyEx(hKey HKEY, index uint32) string {
	var bufLen uint32 = 255
	buf := make([]uint16, bufLen)
	procRegEnumKeyEx.Call(
		uintptr(hKey),
		uintptr(index),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufLen)),
		0,
		0,
		0,
		0)
	return syscall.UTF16ToString(buf)
}

func OpenEventLog(servername string, sourcename string) HANDLE {
	ret, _, _ := procOpenEventLog.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(servername))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(sourcename))))

	return HANDLE(ret)
}

func ReadEventLog(eventlog HANDLE, readflags, recordoffset uint32, buffer []byte, numberofbytestoread uint32, bytesread, minnumberofbytesneeded *uint32) bool {
	ret, _, _ := procReadEventLog.Call(
		uintptr(eventlog),
		uintptr(readflags),
		uintptr(recordoffset),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(numberofbytestoread),
		uintptr(unsafe.Pointer(bytesread)),
		uintptr(unsafe.Pointer(minnumberofbytesneeded)))

	return ret != 0
}

func CloseEventLog(eventlog HANDLE) bool {
	ret, _, _ := procCloseEventLog.Call(
		uintptr(eventlog))

	return ret != 0
}

func OpenSCManager(lpMachineName, lpDatabaseName string, dwDesiredAccess uint32) (HANDLE, error) {
	var p1, p2 uintptr
	if len(lpMachineName) > 0 {
		p1 = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpMachineName)))
	}
	if len(lpDatabaseName) > 0 {
		p2 = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpDatabaseName)))
	}
	ret, _, _ := procOpenSCManager.Call(
		p1,
		p2,
		uintptr(dwDesiredAccess))

	if ret == 0 {
		return 0, syscall.GetLastError()
	}

	return HANDLE(ret), nil
}

func CloseServiceHandle(hSCObject HANDLE) error {
	ret, _, _ := procCloseServiceHandle.Call(uintptr(hSCObject))
	if ret == 0 {
		return syscall.GetLastError()
	}
	return nil
}

func OpenService(hSCManager HANDLE, lpServiceName string, dwDesiredAccess uint32) (HANDLE, error) {
	ret, _, _ := procOpenService.Call(
		uintptr(hSCManager),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpServiceName))),
		uintptr(dwDesiredAccess))

	if ret == 0 {
		return 0, syscall.GetLastError()
	}

	return HANDLE(ret), nil
}

func StartService(hService HANDLE, lpServiceArgVectors []string) error {
	l := len(lpServiceArgVectors)
	var ret uintptr
	if l == 0 {
		ret, _, _ = procStartService.Call(
			uintptr(hService),
			0,
			0)
	} else {
		lpArgs := make([]uintptr, l)
		for i := 0; i < l; i++ {
			lpArgs[i] = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpServiceArgVectors[i])))
		}

		ret, _, _ = procStartService.Call(
			uintptr(hService),
			uintptr(l),
			uintptr(unsafe.Pointer(&lpArgs[0])))
	}

	if ret == 0 {
		return syscall.GetLastError()
	}

	return nil
}

func ControlService(hService HANDLE, dwControl uint32, lpServiceStatus *SERVICE_STATUS) bool {
	if lpServiceStatus == nil {
		panic("ControlService:lpServiceStatus cannot be nil")
	}

	ret, _, _ := procControlService.Call(
		uintptr(hService),
		uintptr(dwControl),
		uintptr(unsafe.Pointer(lpServiceStatus)))

	return ret != 0
}

const (
	TOKEN_ASSIGN_PRIMARY    = 0x0001 // Required to attach a primary token to a process.
	TOKEN_DUPLICATE         = 0x0002 // Required to duplicate an access token.
	TOKEN_IMPERSONATE       = 0x0004 // Required to attach an impersonation access token to a process.
	TOKEN_QUERY             = 0x0008 // Required to query an access token.
	TOKEN_QUERY_SOURCE      = 0x0010 // Required to query the source of an access token.
	TOKEN_ADJUST_PRIVILEGES = 0x0020 // Required to enable or disable the privileges in an access token.
	TOKEN_ADJUST_GROUPS     = 0x0040 // Required to adjust the attributes of the groups in an access token.
	TOKEN_ADJUST_DEFAULT    = 0x0080 // Required to change the default owner, primary group, or DACL of an access token.
	TOKEN_ADJUST_SESSIONID  = 0x0100 // Required to adjust the session ID of an access token. The SE_TCB_NAME privilege is required.
	TOKEN_EXECUTE           = SAR_EXECUTE | TOKEN_IMPERSONATE
	TOKEN_READ              = SAR_READ | TOKEN_QUERY
	TOKEN_WRITE             = SAR_WRITE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT
	TOKEN_ALL_ACCESS        = SAR_REQUIRED | TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID
)

func OpenProcessToken(hProcess HANDLE, dwDesiredAccess uint32, lpTokenHandle *HANDLE) bool {
	if lpTokenHandle == nil {
		panic("OpenProcessToken: lpTokenHandle cannot be nil")
	}
	*lpTokenHandle = 0
	ret, _, _ := procOpenProcessToken.Call(
		uintptr(hProcess),
		uintptr(dwDesiredAccess),
		uintptr(unsafe.Pointer(lpTokenHandle)))

	return ret != 0 && *lpTokenHandle != 0
}

const ( // Privilege Constants - https://msdn.microsoft.com/en-us/library/windows/desktop/bb530716(v=vs.85).aspx
	SE_DEBUG_NAME = "SeDebugPrivilege" // Required to debug and adjust the memory of a process owned by another account.
)

func LookupPrivilegeValue(lpSystemName string, lpName string, lpLUID *LUID) bool {
	if lpLUID == nil {
		panic("LookupPrivilegeValue: lpLUID cannot be nil")
	}
	*lpLUID = 0
	ret, _, _ := procLookupPrivilegeValue.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpSystemName))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpName))),
		uintptr(unsafe.Pointer(lpLUID)))

	return ret != 0 && *lpLUID != 0
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     []LUID_AND_ATTRIBUTES
}

const ( // attributes of a privilege
	SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
	SE_PRIVILEGE_ENABLED            = 0x00000002
	SE_PRIVILEGE_REMOVED            = 0x00000004
	SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000
)

func AdjustTokenPrivileges(hToken HANDLE, disableAllPrivileges bool, newState TOKEN_PRIVILEGES) bool {
	if C.sizeof_struct__X_TOKEN_PRIVILEGES != 4 || C.sizeof_struct__X_LUID_AND_ATTRIBUTES != 12 {
		panic(fmt.Sprintf("AdjustTokenPrivileges: sizeof(TOKEN_PRIVILEGES)=%d sizeof(LUID_AND_ATTRIBUTES)=%d",
			C.sizeof_struct__X_TOKEN_PRIVILEGES, C.sizeof_struct__X_LUID_AND_ATTRIBUTES))
	}
	priv := make([]uint32, (C.sizeof_struct__X_TOKEN_PRIVILEGES+newState.PrivilegeCount*C.sizeof_struct__X_LUID_AND_ATTRIBUTES)/4)
	priv[0] = newState.PrivilegeCount
	for i := uint32(0); i < newState.PrivilegeCount; i++ {
		priv[1+i*3+0] = uint32(newState.Privileges[i].Luid)
		priv[1+i*3+1] = uint32(newState.Privileges[i].Luid >> 32)
		priv[1+i*3+2] = newState.Privileges[i].Attributes
	}

	ret, _, _ := procAdjustTokenPrivileges.Call(
		uintptr(hToken),
		uintptr(BoolToBOOL(disableAllPrivileges)),
		uintptr(unsafe.Pointer(&priv[0])),
		uintptr(0),
		uintptr(0),
		uintptr(0))

	return ret != 0
}

type TokenInformationClass byte

const (
	InvalidTokenInfoClass TokenInformationClass = iota
	TokenUser
	TokenGroups
	TokenPrivileges
	TokenOwner
	TokenPrimaryGroup
	TokenDefaultDacl
	TokenSource
	TokenType
	TokenImpersonationLevel
	TokenStatistics
	TokenRestrictedSids
	TokenSessionId
	TokenGroupsAndPrivileges
	TokenSessionReference
	TokenSandBoxInert
	TokenAuditPolicy
	TokenOrigin
	TokenElevationType
	TokenLinkedToken
	TokenElevation
	TokenHasRestrictions
	TokenAccessInformation
	TokenVirtualizationAllowed
	TokenVirtualizationEnabled
	TokenIntegrityLevel
	TokenUIAccess
	TokenMandatoryPolicy
	TokenLogonSid
	TokenIsAppContainer
	TokenCapabilities
	TokenAppContainerSid
	TokenAppContainerNumber
	TokenUserClaimAttributes
	TokenDeviceClaimAttributes
	TokenRestrictedUserClaimAttributes
	TokenRestrictedDeviceClaimAttributes
	TokenDeviceGroups
	TokenRestrictedDeviceGroups
	TokenSecurityAttributes
	TokenIsRestricted
	MaxTokenInfoClass
)

type TokenElevationTypeResult uint32

const (
	TokenElevationTypeDefault TokenElevationTypeResult = 1
	TokenElevationTypeFull                             = 2
	TokenElevationTypeLimited                          = 3
)

// returns ptr to appropriate Token*Result struct, or nil if error
func GetTokenInformation(hToken HANDLE, tokenInfoClass TokenInformationClass) interface{} {
	switch tokenInfoClass {
	case TokenElevationType:
		var res TokenElevationTypeResult
		expectedLength := uint32(unsafe.Sizeof(res))
		retLength := uint32(0)
		ret, _, _ := procGetTokenInformation.Call(
			uintptr(hToken),
			uintptr(tokenInfoClass),
			uintptr(unsafe.Pointer(&res)),
			uintptr(expectedLength),
			uintptr(unsafe.Pointer(&retLength)))
		if ret != 0 && retLength == expectedLength &&
			res >= TokenElevationTypeDefault && res <= TokenElevationTypeLimited {
			return &res
		}
	case TokenLinkedToken:
		var res HANDLE
		expectedLength := uint32(unsafe.Sizeof(res))
		retLength := uint32(0)
		ret, _, _ := procGetTokenInformation.Call(
			uintptr(hToken),
			uintptr(tokenInfoClass),
			uintptr(unsafe.Pointer(&res)),
			uintptr(expectedLength),
			uintptr(unsafe.Pointer(&retLength)))
		if ret != 0 && retLength == expectedLength {
			return res
		}
	}
	return nil
}

type WellKnownSidType byte

const (
	WinNullSid                                  WellKnownSidType = 0
	WinWorldSid                                                  = 1
	WinLocalSid                                                  = 2
	WinCreatorOwnerSid                                           = 3
	WinCreatorGroupSid                                           = 4
	WinCreatorOwnerServerSid                                     = 5
	WinCreatorGroupServerSid                                     = 6
	WinNtAuthoritySid                                            = 7
	WinDialupSid                                                 = 8
	WinNetworkSid                                                = 9
	WinBatchSid                                                  = 10
	WinInteractiveSid                                            = 11
	WinServiceSid                                                = 12
	WinAnonymousSid                                              = 13
	WinProxySid                                                  = 14
	WinEnterpriseControllersSid                                  = 15
	WinSelfSid                                                   = 16
	WinAuthenticatedUserSid                                      = 17
	WinRestrictedCodeSid                                         = 18
	WinTerminalServerSid                                         = 19
	WinRemoteLogonIdSid                                          = 20
	WinLogonIdsSid                                               = 21
	WinLocalSystemSid                                            = 22
	WinLocalServiceSid                                           = 23
	WinNetworkServiceSid                                         = 24
	WinBuiltinDomainSid                                          = 25
	WinBuiltinAdministratorsSid                                  = 26
	WinBuiltinUsersSid                                           = 27
	WinBuiltinGuestsSid                                          = 28
	WinBuiltinPowerUsersSid                                      = 29
	WinBuiltinAccountOperatorsSid                                = 30
	WinBuiltinSystemOperatorsSid                                 = 31
	WinBuiltinPrintOperatorsSid                                  = 32
	WinBuiltinBackupOperatorsSid                                 = 33
	WinBuiltinReplicatorSid                                      = 34
	WinBuiltinPreWindows2000CompatibleAccessSid                  = 35
	WinBuiltinRemoteDesktopUsersSid                              = 36
	WinBuiltinNetworkConfigurationOperatorsSid                   = 37
	WinAccountAdministratorSid                                   = 38
	WinAccountGuestSid                                           = 39
	WinAccountKrbtgtSid                                          = 40
	WinAccountDomainAdminsSid                                    = 41
	WinAccountDomainUsersSid                                     = 42
	WinAccountDomainGuestsSid                                    = 43
	WinAccountComputersSid                                       = 44
	WinAccountControllersSid                                     = 45
	WinAccountCertAdminsSid                                      = 46
	WinAccountSchemaAdminsSid                                    = 47
	WinAccountEnterpriseAdminsSid                                = 48
	WinAccountPolicyAdminsSid                                    = 49
	WinAccountRasAndIasServersSid                                = 50
	WinNTLMAuthenticationSid                                     = 51
	WinDigestAuthenticationSid                                   = 52
	WinSChannelAuthenticationSid                                 = 53
	WinThisOrganizationSid                                       = 54
	WinOtherOrganizationSid                                      = 55
	WinBuiltinIncomingForestTrustBuildersSid                     = 56
	WinBuiltinPerfMonitoringUsersSid                             = 57
	WinBuiltinPerfLoggingUsersSid                                = 58
	WinBuiltinAuthorizationAccessSid                             = 59
	WinBuiltinTerminalServerLicenseServersSid                    = 60
	WinBuiltinDCOMUsersSid                                       = 61
	WinBuiltinIUsersSid                                          = 62
	WinIUserSid                                                  = 63
	WinBuiltinCryptoOperatorsSid                                 = 64
	WinUntrustedLabelSid                                         = 65
	WinLowLabelSid                                               = 66
	WinMediumLabelSid                                            = 67
	WinHighLabelSid                                              = 68
	WinSystemLabelSid                                            = 69
	WinWriteRestrictedCodeSid                                    = 70
	WinCreatorOwnerRightsSid                                     = 71
	WinCacheablePrincipalsGroupSid                               = 72
	WinNonCacheablePrincipalsGroupSid                            = 73
	WinEnterpriseReadonlyControllersSid                          = 74
	WinAccountReadonlyControllersSid                             = 75
	WinBuiltinEventLogReadersGroup                               = 76
	WinNewEnterpriseReadonlyControllersSid                       = 77
	WinBuiltinCertSvcDComAccessGroup                             = 78
	WinMediumPlusLabelSid                                        = 79
	WinLocalLogonSid                                             = 80
	WinConsoleLogonSid                                           = 81
	WinThisOrganizationCertificateSid                            = 82
	WinApplicationPackageAuthoritySid                            = 83
	WinBuiltinAnyPackageSid                                      = 84
	WinCapabilityInternetClientSid                               = 85
	WinCapabilityInternetClientServerSid                         = 86
	WinCapabilityPrivateNetworkClientServerSid                   = 87
	WinCapabilityPicturesLibrarySid                              = 88
	WinCapabilityVideosLibrarySid                                = 89
	WinCapabilityMusicLibrarySid                                 = 90
	WinCapabilityDocumentsLibrarySid                             = 91
	WinCapabilitySharedUserCertificatesSid                       = 92
	WinCapabilityEnterpriseAuthenticationSid                     = 93
	WinCapabilityRemovableStorageSid                             = 94
)

type SID []byte

const SECURITY_MAX_SID_SIZE = 68

func CreateWellKnownSid(wks WellKnownSidType) SID {
	sid := make([]byte, SECURITY_MAX_SID_SIZE+1)
	sidLen := uint32(len(sid))
	ret, _, _ := procCreateWellKnownSid.Call(
		uintptr(wks),
		uintptr(0),
		uintptr(unsafe.Pointer(&sid[0])),
		uintptr(unsafe.Pointer(&sidLen)))
	if ret != 0 && sidLen > 0 && sidLen <= SECURITY_MAX_SID_SIZE {
		return SID(sid[:sidLen])
	}
	return nil
}

func CheckTokenMembership(hToken HANDLE, sidToCheck SID) bool {
	isMember := uint32(9)
	ret, _, _ := procCheckTokenMembership.Call(
		uintptr(hToken),
		uintptr(unsafe.Pointer(&sidToCheck[0])),
		uintptr(unsafe.Pointer(&isMember)))
	return ret != 0 && isMember == 1
}
