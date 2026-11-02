//go:build windows

// from github.com/iamacarpet/go-win64api (MIT, see LICENSE).
// only what ListLoggedInUsers needs. builds for every windows arch.

package winapi

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	so "github.com/iamacarpet/go-win64api/shared"
)

var (
	modSecur32                    = syscall.NewLazyDLL("secur32.dll")
	sessLsaFreeReturnBuffer       = modSecur32.NewProc("LsaFreeReturnBuffer")
	sessLsaEnumerateLogonSessions = modSecur32.NewProc("LsaEnumerateLogonSessions")
	sessLsaGetLogonSessionData    = modSecur32.NewProc("LsaGetLogonSessionData")
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type SECURITY_LOGON_SESSION_DATA struct {
	Size                  uint32
	LogonId               LUID
	UserName              LSA_UNICODE_STRING
	LogonDomain           LSA_UNICODE_STRING
	AuthenticationPackage LSA_UNICODE_STRING
	LogonType             uint32
	Session               uint32
	Sid                   uintptr
	LogonTime             uint64
	LogonServer           LSA_UNICODE_STRING
	DnsDomainName         LSA_UNICODE_STRING
	Upn                   LSA_UNICODE_STRING
}

type LSA_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	buffer        *uint16
}

func ListLoggedInUsers() ([]so.SessionDetails, error) {
	var (
		logonSessionCount uint64
		loginSessionList  uintptr
		sizeTest          LUID
		uList             []string            = make([]string, 0)
		uSessList         []so.SessionDetails = make([]so.SessionDetails, 0)
		PidLUIDList       map[uint32]SessionLUID
	)
	PidLUIDList, err := ProcessLUIDList()
	if err != nil {
		return nil, fmt.Errorf("Error getting process list, %s.", err.Error())
	}

	_, _, _ = sessLsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&logonSessionCount)),
		uintptr(unsafe.Pointer(&loginSessionList)),
	)
	defer sessLsaFreeReturnBuffer.Call(loginSessionList)

	var iter uintptr = loginSessionList

	for i := uint64(0); i < logonSessionCount; i++ {
		var sessionData *SECURITY_LOGON_SESSION_DATA
		_, _, _ = sessLsaGetLogonSessionData.Call(uintptr(iter), uintptr(unsafe.Pointer(&sessionData)))
		if sessionData != nil {
			var data *SECURITY_LOGON_SESSION_DATA = sessionData

			if data.Sid != uintptr(0) {
				validTypes := []uint32{so.SESS_INTERACTIVE_LOGON, so.SESS_CACHED_INTERACTIVE_LOGON, so.SESS_REMOTE_INTERACTIVE_LOGON}
				if in_array(data.LogonType, validTypes) {
					strLogonDomain := strings.ToUpper(LsatoString(data.LogonDomain))
					if strLogonDomain != "WINDOW MANAGER" && strLogonDomain != "FONT DRIVER HOST" {
						sUser := fmt.Sprintf("%s\\%s", strings.ToUpper(LsatoString(data.LogonDomain)), strings.ToLower(LsatoString(data.UserName)))
						sort.Strings(uList)
						i := sort.Search(len(uList), func(i int) bool { return uList[i] >= sUser })
						if !(i < len(uList) && uList[i] == sUser) {
							if uok, isAdmin := luidinmap(&data.LogonId, &PidLUIDList); uok {
								uList = append(uList, sUser)
								ud := so.SessionDetails{
									Username:      strings.ToLower(LsatoString(data.UserName)),
									Domain:        strLogonDomain,
									LocalAdmin:    isAdmin,
									LogonType:     data.LogonType,
									DnsDomainName: LsatoString(data.DnsDomainName),
									LogonTime:     uint64TimestampToTime(data.LogonTime),
								}
								hn, _ := os.Hostname()
								if strings.ToUpper(ud.Domain) == strings.ToUpper(hn) {
									ud.LocalUser = true
									if isAdmin, _ := IsLocalUserAdmin(ud.Username); isAdmin {
										ud.LocalAdmin = true
									}
								} else {
									if isAdmin, _ := IsDomainUserAdmin(ud.Username, LsatoString(data.DnsDomainName)); isAdmin {
										ud.LocalAdmin = true
									}
								}
								uSessList = append(uSessList, ud)
							}
						}
					}
				}
			}
		}

		iter += unsafe.Sizeof(sizeTest)
		_, _, _ = sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(sessionData)))
	}

	return uSessList, nil
}

func uint64TimestampToTime(nsec uint64) time.Time {
	// change starting time to the Epoch (00:00:00 UTC, January 1, 1970)
	nsec -= 116444736000000000
	// convert into nanoseconds
	nsec *= 100

	return time.Unix(0, int64(nsec))
}

func luidinmap(needle *LUID, haystack *map[uint32]SessionLUID) (bool, bool) {
	for _, l := range *haystack {
		if reflect.DeepEqual(l.Value, *needle) {
			if l.IsAdmin {
				return true, true
			} else {
				return true, false
			}
		}
	}
	return false, false
}

func LsatoString(p LSA_UNICODE_STRING) string {
	// Length counts bytes, not characters.
	return syscall.UTF16ToString(unsafe.Slice(p.buffer, p.Length/2))
}

func in_array(val interface{}, array interface{}) (exists bool) {
	exists = false

	switch reflect.TypeOf(array).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(array)

		for i := 0; i < s.Len(); i++ {
			if reflect.DeepEqual(val, s.Index(i).Interface()) == true {
				exists = true
				return
			}
		}
	}

	return
}

var (
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle              = modKernel32.NewProc("CloseHandle")
	procOpenProcess              = modKernel32.NewProc("OpenProcess")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modKernel32.NewProc("Process32FirstW")
	procProcess32Next            = modKernel32.NewProc("Process32NextW")
	procGetCurrentProcess        = modKernel32.NewProc("GetCurrentProcess")
	modAdvapi32                  = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken         = modAdvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValue     = modAdvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges    = modAdvapi32.NewProc("AdjustTokenPrivileges")
	procGetTokenInformation      = modAdvapi32.NewProc("GetTokenInformation")
	procCheckTokenMembership     = modAdvapi32.NewProc("CheckTokenMembership")
	procAllocateAndInitializeSid = modAdvapi32.NewProc("AllocateAndInitializeSid")
	procFreeSid                  = modAdvapi32.NewProc("FreeSid")
	procDuplicateToken           = modAdvapi32.NewProc("DuplicateToken")
)

const (
	PROCESS_QUERY_INFORMATION        = 0x0400
	MAX_PATH                         = 260
	PROC_TOKEN_DUPLICATE             = 0x0002
	PROC_TOKEN_QUERY                 = 0x0008
	PROC_TOKEN_ADJUST_PRIVILEGES     = 0x0020
	PROC_SE_PRIVILEGE_ENABLED        = 0x00000002
	PROC_SE_DEBUG_NAME               = "SeDebugPrivilege"
	PROC_SECURITY_BUILTIN_DOMAIN_RID = 0x00000020
	PROC_DOMAIN_ALIAS_RID_ADMINS     = 0x00000220
	PROC_ERROR_NO_SUCH_LOGON_SESSION = 1312
	PROC_ERROR_PRIVILEGE_NOT_HELD    = 1314
)

// PROCESSENTRY32 is the Windows API structure that contains a process's
// information.
type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

type LUID_AND_ATTRIBUTES struct {
	LUID       LUID
	Attributes uint32
}

type TOKEN_STATISTICS struct {
	TokenId            LUID
	AuthenticationId   LUID
	ExpirationTime     uint64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedId         LUID
}

type PSID uintptr

type SID_IDENTIFIER_AUTHORITY struct {
	Value [6]byte
}

type SessionLUID struct {
	Value   LUID
	IsAdmin bool
}

func ProcessLUIDList() (map[uint32]SessionLUID, error) {
	err := procAssignCorrectPrivs(PROC_SE_DEBUG_NAME)
	if err != nil {
		return nil, fmt.Errorf("Error assigning privs... %s", err.Error())
	}

	handle, _, _ := procCreateToolhelp32Snapshot.Call(0x00000002, 0)
	if handle < 0 {
		return nil, syscall.GetLastError()
	}
	defer procCloseHandle.Call(handle)

	pMap := make(map[uint32]SessionLUID)

	var entry PROCESSENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := procProcess32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Error retrieving process info.")
	}

	for {
		ll, isAdmin, _ := getProcessLUID(entry.ProcessID)

		pMap[entry.ProcessID] = SessionLUID{
			Value:   ll,
			IsAdmin: isAdmin,
		}

		ret, _, _ := procProcess32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return pMap, nil
}

func procAssignCorrectPrivs(name string) error {
	handle, _, _ := procGetCurrentProcess.Call()
	if handle == uintptr(0) {
		return fmt.Errorf("Unable to get current process handle.")
	}
	defer procCloseHandle.Call(handle)

	var tHandle uintptr
	opRes, _, _ := procOpenProcessToken.Call(
		uintptr(handle),
		uintptr(uint32(PROC_TOKEN_ADJUST_PRIVILEGES)),
		uintptr(unsafe.Pointer(&tHandle)),
	)
	if opRes != 1 {
		return fmt.Errorf("Unable to open current process token.")
	}
	defer procCloseHandle.Call(tHandle)

	nPointer, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("Unable to encode SE_DEBUG_NAME to UTF16")
	}
	var pValue LUID
	lpRes, _, _ := procLookupPrivilegeValue.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(nPointer)),
		uintptr(unsafe.Pointer(&pValue)),
	)
	if lpRes != 1 {
		return fmt.Errorf("Unable to lookup priv value.")
	}

	iVal := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
	}
	iVal.Privileges[0] = LUID_AND_ATTRIBUTES{
		LUID:       pValue,
		Attributes: PROC_SE_PRIVILEGE_ENABLED,
	}
	ajRes, _, _ := procAdjustTokenPrivileges.Call(
		uintptr(tHandle),
		uintptr(uint32(0)),
		uintptr(unsafe.Pointer(&iVal)),
		uintptr(uint32(0)),
		uintptr(0),
		uintptr(0),
	)
	if ajRes != 1 {
		return fmt.Errorf("Error while adjusting process token.")
	}
	return nil
}

func getProcessLUID(pid uint32) (retLUID LUID, isAdmin bool, retError error) {
	retLUID = LUID{}

	handle, _, lastError := procOpenProcess.Call(uintptr(uint32(PROCESS_QUERY_INFORMATION)), uintptr(0), uintptr(pid))
	if handle < 0 {
		retError = lastError
		return
	}
	defer procCloseHandle.Call(handle)

	var ptHandle uintptr
	opRes, _, _ := procOpenProcessToken.Call(
		uintptr(handle),
		uintptr(uint32(PROC_TOKEN_QUERY)),
		uintptr(unsafe.Pointer(&ptHandle)),
	)
	if opRes != 1 {
		retError = fmt.Errorf("Unable to open process token.")
		return
	}
	defer procCloseHandle.Call(ptHandle)

	var sData TOKEN_STATISTICS
	var sLength uint32
	tsRes, _, _ := procGetTokenInformation.Call(
		uintptr(ptHandle),
		uintptr(uint32(10)), // TOKEN_STATISTICS
		uintptr(unsafe.Pointer(&sData)),
		uintptr(uint32(unsafe.Sizeof(sData))),
		uintptr(unsafe.Pointer(&sLength)),
	)
	if tsRes != 1 {
		retError = fmt.Errorf("Error fetching token information (LUID).")
		return
	}
	retLUID = sData.AuthenticationId

	// Grab the token again for the next bit,
	// as if we try and combine this with the first bit,
	// the token grab will fail unless run as NT AUTHORITY\SYSTEM
	var tHandle uintptr
	opRes2, _, _ := procOpenProcessToken.Call(
		uintptr(handle),
		uintptr(uint32(PROC_TOKEN_QUERY|PROC_TOKEN_DUPLICATE)),
		uintptr(unsafe.Pointer(&tHandle)),
	)
	if opRes2 != 1 {
		retError = fmt.Errorf("Unable to open process token.")
		return
	}
	defer procCloseHandle.Call(tHandle)

	// Generate an SID for the Administrators group.
	NtAuthority := SID_IDENTIFIER_AUTHORITY{
		Value: [6]byte{0, 0, 0, 0, 0, 5}, // SECURITY_NT_AUTHORITY
	}
	var AdministratorsGroup PSID
	sidRes, _, _ := procAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&NtAuthority)),
		uintptr(uint8(2)),
		uintptr(uint32(PROC_SECURITY_BUILTIN_DOMAIN_RID)),
		uintptr(uint32(PROC_DOMAIN_ALIAS_RID_ADMINS)),
		uintptr(0), uintptr(0), uintptr(0), uintptr(0), uintptr(0), uintptr(0),
		uintptr(unsafe.Pointer(&AdministratorsGroup)),
	)
	if sidRes != 1 {
		retError = fmt.Errorf("Error generating Administrators SID for group membership check")
		return
	}
	defer procFreeSid.Call(uintptr(AdministratorsGroup))

	// Duplicate the token...
	var ttHandle uintptr
	dupRes, _, lastError := procDuplicateToken.Call(
		uintptr(tHandle),
		uintptr(1), // _SECURITY_IMPERSONATION_LEVEL = SecurityIdentification
		uintptr(unsafe.Pointer(&ttHandle)),
	)
	defer procCloseHandle.Call(ttHandle)
	if dupRes != 1 {
		retError = fmt.Errorf("Error generating impersonation token: %s", lastError)
		return
	}

	// Check token for membership of the Administrators group.
	var chkRes bool
	mbrRes, _, _ := procCheckTokenMembership.Call(
		uintptr(ttHandle),
		uintptr(AdministratorsGroup),
		uintptr(unsafe.Pointer(&chkRes)),
	)
	if mbrRes != 1 {
		retError = fmt.Errorf("Error checking group membership")
		return
	} else {
		isAdmin = chkRes
	}

	var ltHandle uintptr
	var length uint32
	ltokRes, _, lastError := procGetTokenInformation.Call(
		uintptr(tHandle),
		uintptr(19), // TokenLinkedToken
		uintptr(unsafe.Pointer(&ltHandle)),
		uintptr(uint32(unsafe.Sizeof(ltHandle))),
		uintptr(unsafe.Pointer(&length)),
	)
	if ltokRes != 1 {
		if lastError.(syscall.Errno) == PROC_ERROR_NO_SUCH_LOGON_SESSION || lastError.(syscall.Errno) == PROC_ERROR_PRIVILEGE_NOT_HELD {
			return
		} else {
			retError = fmt.Errorf("Error getting linked token: %d: %s", lastError.(syscall.Errno), lastError)
			return
		}
	}
	defer procCloseHandle.Call(ltHandle)

	var lttHandle uintptr
	dup2Res, _, lastError := procDuplicateToken.Call(
		uintptr(ltHandle),
		uintptr(1), // _SECURITY_IMPERSONATION_LEVEL = SecurityIdentification
		uintptr(unsafe.Pointer(&lttHandle)),
	)
	if dup2Res != 1 {
		retError = fmt.Errorf("Error generating impersonation token (2): %s", lastError)
		return
	}
	defer procCloseHandle.Call(lttHandle)

	mbr2Res, _, lastError := procCheckTokenMembership.Call(
		uintptr(lttHandle),
		uintptr(AdministratorsGroup),
		uintptr(unsafe.Pointer(&chkRes)),
	)
	if mbr2Res != 1 {
		retError = fmt.Errorf("Error checking group membership (2): %s", lastError)
		return
	} else {
		isAdmin = chkRes
	}

	return
}

var (
	modNetapi32         = syscall.NewLazyDLL("netapi32.dll")
	usrNetGetAnyDCName  = modNetapi32.NewProc("NetGetAnyDCName")
	usrNetUserGetInfo   = modNetapi32.NewProc("NetUserGetInfo")
	usrNetApiBufferFree = modNetapi32.NewProc("NetApiBufferFree")
)

const (
	USER_PRIV_ADMIN = 2
)

type USER_INFO_1 struct {
	Usri1_name         *uint16
	Usri1_password     *uint16
	Usri1_password_age uint32
	Usri1_priv         uint32
	Usri1_home_dir     *uint16
	Usri1_comment      *uint16
	Usri1_flags        uint32
	Usri1_script_path  *uint16
}

// IsLocalUserAdmin returns whether the user with the specified user name has
// administration rights on the local machine.
func IsLocalUserAdmin(username string) (bool, error) {
	var dataPointer *USER_INFO_1
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("unable to encode username to UTF16")
	}
	_, _, _ = usrNetUserGetInfo.Call(
		uintptr(0),                            // servername
		uintptr(unsafe.Pointer(uPointer)),     // username
		uintptr(uint32(1)),                    // level, request USER_INFO_1
		uintptr(unsafe.Pointer(&dataPointer)), // Pointer to struct.
	)
	defer usrNetApiBufferFree.Call(uintptr(unsafe.Pointer(dataPointer)))

	if dataPointer == nil {
		return false, fmt.Errorf("unable to get data structure")
	}

	var data = dataPointer

	if data.Usri1_priv == USER_PRIV_ADMIN {
		return true, nil
	} else {
		return false, nil
	}
}

// IsDomainUserAdmin returns whether the specified user is an administrator for
// the specified domain.
func IsDomainUserAdmin(username string, domain string) (bool, error) {
	var dataPointer *USER_INFO_1
	var dcPointer uintptr
	uPointer, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false, fmt.Errorf("unable to encode username to UTF16")
	}
	dPointer, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return false, fmt.Errorf("unable to encode domain to UTF16")
	}

	_, _, _ = usrNetGetAnyDCName.Call(
		uintptr(0),                        // servername
		uintptr(unsafe.Pointer(dPointer)), // domainame
		uintptr(unsafe.Pointer(&dcPointer)),
	)
	defer usrNetApiBufferFree.Call(dcPointer)

	_, _, _ = usrNetUserGetInfo.Call(
		uintptr(dcPointer),                    // servername
		uintptr(unsafe.Pointer(uPointer)),     // username
		uintptr(uint32(1)),                    // level, request USER_INFO_1
		uintptr(unsafe.Pointer(&dataPointer)), // Pointer to struct.
	)
	defer usrNetApiBufferFree.Call(uintptr(unsafe.Pointer(dataPointer)))

	if dataPointer == nil {
		return false, fmt.Errorf("unable to get data structure")
	}

	var data = dataPointer

	if data.Usri1_priv == USER_PRIV_ADMIN {
		return true, nil
	} else {
		return false, nil
	}
}
