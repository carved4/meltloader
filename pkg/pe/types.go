package pe

import (
	"fmt"
	"unsafe"
)

const (
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 0x5
	DLL_PROCESS_ATTACH              = 0x1
	MEM_COMMIT                      = 0x00001000
	MEM_RESERVE                     = 0x00002000
	MEM_RELEASE                     = 0x00008000
	PAGE_NOACCESS                   = 0x01
	PAGE_EXECUTE_READWRITE          = 0x40
	PAGE_READWRITE                  = 0x04
	PAGE_EXECUTE_READ               = 0x20
	PAGE_READONLY                   = 0x02
	THREAD_SUSPEND_RESUME           = 0x0002
	THREAD_ALL_ACCESS               = 0x1FFFFF
)

type ULONGLONG uint64

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32

	DataDirectory [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type BASE_RELOCATION_BLOCK struct {
	PageAddress uint32
	BlockSize   uint32
}

type BASE_RELOCATION_ENTRY struct {
	OffsetType uint16
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	OriginalFirstThunk uint32 // union with Characteristics
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

type ImageThunkData64 struct {
	AddressOfData uintptr
}

type ImageThunkData = ImageThunkData64
type OriginalImageThunkData = ImageThunkData64

type ImageReloc struct {
	Data uint16
}

func (r *ImageReloc) GetType() uint16 {
	return (r.Data >> 12) & 0xF
}

func (r *ImageReloc) GetOffset() uint16 {
	return r.Data & 0xFFF
}

// VEH Exception handling structures (future)
type EXCEPTION_RECORD struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      *EXCEPTION_RECORD
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [15]uintptr
}

type EXCEPTION_POINTERS struct {
	ExceptionRecord *EXCEPTION_RECORD
	ContextRecord   *CONTEXT
}

func NtH(baseAddress uintptr) *IMAGE_NT_HEADERS {
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(baseAddress))
	return (*IMAGE_NT_HEADERS)(unsafe.Pointer(baseAddress + uintptr(dosHeader.E_lfanew)))
}

func CstrVal(ptr unsafe.Pointer) []byte {
	var result []byte
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i)))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return result
}

func IsMSBSet(value uintptr) bool {
	return (value & 0x8000000000000000) != 0
}

func ParseOrdinal(addressOfData uintptr) (unsafe.Pointer, string) {
	ord := uint16(addressOfData & 0xFFFF)
	return unsafe.Pointer(uintptr(ord)), fmt.Sprintf("#%d", ord)
}

func ParseFuncAddress(baseAddress uintptr, addressOfData uintptr) (unsafe.Pointer, string) {
	nameAddr := baseAddress + addressOfData + 2 // Skip hint
	nameBytes := CstrVal(unsafe.Pointer(nameAddr))
	return unsafe.Pointer(nameAddr), string(nameBytes)
}

func GetRelocTable(ntHeaders *IMAGE_NT_HEADERS) *IMAGE_DATA_DIRECTORY {
	if ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0 {
		return nil
	}
	return &ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
}

func Memcpy(dst, src uintptr, size uintptr) {
	srcSlice := (*[^uint32(0)]byte)(unsafe.Pointer(src))[:size:size]
	dstSlice := (*[^uint32(0)]byte)(unsafe.Pointer(dst))[:size:size]
	copy(dstSlice, srcSlice)
}

func Memset(ptr uintptr, value byte, size uintptr) {
	slice := (*[^uint32(0)]byte)(unsafe.Pointer(ptr))[:size:size]
	for i := range slice {
		slice[i] = value
	}
}

func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

type M128A struct {
	Low  uint64
	High int64
}

type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	VectorRegister       [26]M128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

type UString struct {
	Length        uint32
	MaximumLength uint32
	Buffer        *byte // This corresponds to PUCHAR in C
}

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type PROCESS_INFORMATION struct {
	HProcess  uintptr
	HThread   uintptr
	ProcessId uint32
	ThreadId  uint32
}

type STARTUPINFO struct {
	Cb            uint32
	LpReserved    *uint16
	LpDesktop     *uint16
	LpTitle       *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	CbReserved2   uint16
	LpReserved2   *byte
	HStdInput     uintptr
	HStdOutput    uintptr
	HStdError     uintptr
}
type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

func (bre BASE_RELOCATION_ENTRY) Offset() uint16 {
	return bre.OffsetType & 0xFFF
}

func (bre BASE_RELOCATION_ENTRY) Type() uint16 {
	return (bre.OffsetType >> 12) & 0xF
}

const (
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0x0
	IMAGE_DIRECTORY_ENTRY_IMPORT = 0x1
	IMAGE_DIRECTORY_ENTRY_TLS    = 0x9
)

// TLS directory for x64
type IMAGE_TLS_DIRECTORY64 struct {
	StartAddressOfRawData uint64
	EndAddressOfRawData   uint64
	AddressOfIndex        uint64
	AddressOfCallBacks    uint64
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

// ---------------------------------------------------------------------------
// AFD (Ancillary Function Driver) types for raw socket I/O via \Device\Afd
// ---------------------------------------------------------------------------

const (
	AF_INET     = 2
	SOCK_STREAM = 1
	IPPROTO_TCP = 6

	IOCTL_AFD_BIND    = 0x00012003
	IOCTL_AFD_CONNECT = 0x00012007
	IOCTL_AFD_SEND    = 0x0001201F
	IOCTL_AFD_RECV    = 0x00012017

	OBJ_CASE_INSENSITIVE         = 0x00000040
	FILE_OPEN_IF                 = 0x00000003
	FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

	EVENT_ALL_ACCESS = 0x1F0003
)

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	_                        uint32 // padding on x64
	RootDirectory            uintptr
	ObjectName               *UNICODE_STRING
	Attributes               uint32
	_                        uint32 // padding on x64
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type IO_STATUS_BLOCK struct {
	Status      uintptr
	Information uintptr
}

type IN_ADDR struct {
	S_addr uint32
}

type SOCKADDR_IN struct {
	Sin_family int16
	Sin_port   uint16
	Sin_addr   IN_ADDR
	Sin_zero   [8]byte
}

type AFD_OPEN_PACKET_EXTENDED_ATTRIBUTES struct {
	NextEntryOffset              uint32
	Flags                        byte
	ExtendedAttributeNameLength  byte
	ExtendedAttributeValueLength uint16
	ExtendedAttributeName        [16]byte
	EndpointFlags                uint32
	GroupID                      uint32
	AddressFamily                uint32
	SocketType                   uint32
	Protocol                     uint32
	SizeOfTransportName          uint32
	Unknown1                     [9]byte
}

type AFD_BIND_SOCKET struct {
	Flags   uint32
	Address SOCKADDR_IN
}

type AFD_CONNECT_REQUEST_IPV4 struct {
	SharedAccessNamespaceActive uint64
	RootEndpoint                uint64
	ConnectEndpoint             uint64
	Address                     SOCKADDR_IN
}

type AFD_IO_BUFFER struct {
	Length uint32
	_      uint32 // padding on x64
	Buffer uintptr
}

type AFD_TRANSFER_REQUEST struct {
	Buffer      *AFD_IO_BUFFER
	BufferCount uint32
	AfdFlags    uint32
	TdiFlags    uint32
}

// ---------------------------------------------------------------------------
// SSPI / SChannel / TLS types
// ---------------------------------------------------------------------------

const (
	SECBUFFER_VERSION        = 0
	SECBUFFER_EMPTY          = 0
	SECBUFFER_DATA           = 1
	SECBUFFER_TOKEN          = 2
	SECBUFFER_EXTRA          = 5
	SECBUFFER_STREAM_TRAILER = 6
	SECBUFFER_STREAM_HEADER  = 7

	SECURITY_NATIVE_DREP            = 0x00000010
	SECPKG_ATTR_STREAM_SIZES        = 4
	SECPKG_ATTR_REMOTE_CERT_CONTEXT = 0x53

	ISC_REQ_REPLAY_DETECT   = 0x00000004
	ISC_REQ_SEQUENCE_DETECT = 0x00000008
	ISC_REQ_CONFIDENTIALITY = 0x00000010
	ISC_REQ_ALLOCATE_MEMORY = 0x00000100
	ISC_REQ_EXTENDED_ERROR  = 0x00004000
	ISC_REQ_STREAM          = 0x00008000

	SCHANNEL_CRED_VERSION = 0x00000004
	SCHANNEL_SHUTDOWN     = 0x00000001

	SEC_E_OK                 = 0
	SEC_I_CONTINUE_NEEDED    = 0x00090312
	SEC_E_INCOMPLETE_MESSAGE = int32(-2146893032) // 0x80090318
	SEC_I_CONTEXT_EXPIRED    = 0x00090317
	SEC_I_RENEGOTIATE        = 0x00090321

	AUTHTYPE_SERVER = 1
)

type SecHandle struct {
	DwLower uintptr
	DwUpper uintptr
}

type SecBuffer struct {
	CbBuffer   uint32
	BufferType uint32
	PvBuffer   uintptr
}

type SecBufferDesc struct {
	UlVersion uint32
	CBuffers  uint32
	PBuffers  *SecBuffer
}

type SECURITY_INTEGER struct {
	LowPart  uint32
	HighPart uint32
}

type SecPkgContext_StreamSizes struct {
	CbHeader         uint32
	CbTrailer        uint32
	CbMaximumMessage uint32
	CBuffers         uint32
	CbBlockSize      uint32
}

type SCHANNEL_CRED struct {
	DwVersion               uint32
	CCreds                  uint32
	PaCred                  uintptr
	HRootStore              uintptr
	CMappers                uint32
	_                       uint32 // padding
	AphMappers              uintptr
	CSupportedAlgs          uint32
	_                       uint32 // padding
	PalgSupportedAlgs       uintptr
	GrbitEnabledProtocols   uint32
	DwMinimumCipherStrength uint32
	DwMaximumCipherStrength uint32
	DwSessionLifespan       uint32
	DwFlags                 uint32
	DwCredFormat            uint32
}

// SecurityFunctionTableW mirrors the SSPI function table layout.
// We only store the function pointers we actually need; the rest are padding.
type SecurityFunctionTableW struct {
	DwVersion                   uint32
	_                           uint32 // padding
	EnumerateSecurityPackagesW  uintptr
	QueryCredentialsAttributesW uintptr
	AcquireCredentialsHandleW   uintptr
	FreeCredentialsHandle       uintptr
	Reserved2                   uintptr
	InitializeSecurityContextW  uintptr
	AcceptSecurityContext       uintptr
	CompleteAuthToken           uintptr
	DeleteSecurityContext       uintptr
	ApplyControlToken           uintptr
	QueryContextAttributesW     uintptr
	ImpersonateSecurityContext  uintptr
	RevertSecurityContext       uintptr
	MakeSignature               uintptr
	VerifySignature             uintptr
	FreeContextBuffer           uintptr
	QuerySecurityPackageInfoW   uintptr
	Reserved3                   uintptr
	Reserved4                   uintptr
	ExportSecurityContext       uintptr
	ImportSecurityContextW      uintptr
	AddCredentialsW             uintptr
	Reserved8                   uintptr
	QuerySecurityContextToken   uintptr
	EncryptMessage              uintptr
	DecryptMessage              uintptr
	SetContextAttributesW       uintptr
	SetCredentialsAttributesW   uintptr
	Reserved9                   uintptr
}

// TLSClient holds the state for a single TLS session.
type TLSClient struct {
	CredentialHandle      SecHandle
	ContextHandle         SecHandle
	CredentialInitialized bool
	ContextInitialized    bool
	Sizes                 SecPkgContext_StreamSizes
}

// ---------------------------------------------------------------------------
// Cert verification types (for TLS handshake chain validation)
// ---------------------------------------------------------------------------

type CERT_CHAIN_PARA struct {
	CbSize uint32
	_      [108]byte // remaining fields we zero-init
}

type SSL_EXTRA_CERT_CHAIN_POLICY_PARA struct {
	CbSize         uint32
	DwAuthType     uint32
	FdwChecks      uint32
	_              uint32 // padding
	PwszServerName *uint16
}

type CERT_CHAIN_POLICY_PARA struct {
	CbSize            uint32
	DwFlags           uint32
	PvExtraPolicyPara uintptr
}

type CERT_CHAIN_POLICY_STATUS struct {
	CbSize              uint32
	DwError             uint32
	LChainIndex         int32
	LElementIndex       int32
	PvExtraPolicyStatus uintptr
}

// ---------------------------------------------------------------------------
// DNS types
// ---------------------------------------------------------------------------

type DNS_HEADER struct {
	Id      uint16
	Flags   uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}
