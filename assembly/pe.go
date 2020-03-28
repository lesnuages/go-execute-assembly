package assembly


type(
	DWORD           uint32
)

const (
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_FILE_MACHINE_I386          = 0x014c
	IMAGE_FILE_MACHINE_AMD64         = 0x8664
	DLL_PROCESS_ATTACH               = 1
	DLL_THREAD_ATTACH                = 2
	DLL_THREAD_DETACH                = 3
	DLL_PROCESS_DETACH               = 0

	IMAGE_DIRECTORY_ENTRY_EXPORT         = 0  // Export Directory
	IMAGE_DIRECTORY_ENTRY_IMPORT         = 1  // Import Directory
	IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2  // Resource Directory
	IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3  // Exception Directory
	IMAGE_DIRECTORY_ENTRY_SECURITY       = 4  // Security Directory
	IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5  // Base Relocation Table
	IMAGE_DIRECTORY_ENTRY_DEBUG          = 6  // Debug Directory
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7  // Architecture Specific Data
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8  // RVA of GP
	IMAGE_DIRECTORY_ENTRY_TLS            = 9  // TLS Directory
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10 // Load Configuration Directory
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11 // Bound Import Directory in headers
	IMAGE_DIRECTORY_ENTRY_IAT            = 12 // Import Address Table
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13 // Delay Load Import Descriptors
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 // COM Runtime descriptor
	IMAGE_REL_BASED_HIGHLOW              = 3
	IMAGE_REL_BASED_DIR64                = 10
	IMAGE_ORDINAL_FLAG64                 = 0x8000000000000000
	IMAGE_ORDINAL_FLAG32                 = 0x80000000
)

type ULONGLONG uint64

type LONG uint32
type WORD uint16
type BOOL uint8
type BYTE uint8

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress DWORD
	SizeOfBlock    DWORD
	//  WORD    TypeOffset[1];
}

type IMAGE_IMPORT_BY_NAME struct {
	Hint WORD
	Name [1]uint8
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	/*
		union {
		DWORD   Characteristics;            // 0 for terminating null import descriptor
		DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
		} DUMMYUNIONNAME;
		DWORD   TimeDateStamp;                  // 0 if not bound,
		// -1 if bound, and real date\time stamp
		//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
		// O.W. date/time stamp of DLL bound to (Old BIND)

		DWORD   ForwarderChain;                 // -1 if no forwarders
		DWORD   Name;
		DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)

	*/
	OriginalFirstThunk DWORD
	TimeDateStamp      DWORD
	ForwarderChain     DWORD
	Name               DWORD
	FirstThunk         DWORD
}

type _IMAGE_NT_HEADERS64 struct {
	Signature      DWORD
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}
type IMAGE_NT_HEADERS64 _IMAGE_NT_HEADERS64
type IMAGE_NT_HEADERS IMAGE_NT_HEADERS64

type _IMAGE_DATA_DIRECTORY struct {
	VirtualAddress DWORD
	Size           DWORD
}
type IMAGE_DATA_DIRECTORY _IMAGE_DATA_DIRECTORY

type _IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_OPTIONAL_HEADER64 _IMAGE_OPTIONAL_HEADER64
type IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64

type _IMAGE_FILE_HEADER struct {
	Machine              WORD
	NumberOfSections     WORD
	TimeDateStamp        DWORD
	PointerToSymbolTable DWORD
	NumberOfSymbols      DWORD
	SizeOfOptionalHeader WORD
	Characteristics      WORD
}

type IMAGE_FILE_HEADER _IMAGE_FILE_HEADER

type _IMAGE_DOS_HEADER struct { // DOS .EXE header
	E_magic    WORD     // Magic number
	E_cblp     WORD     // Bytes on last page of file
	E_cp       WORD     // Pages in file
	E_crlc     WORD     // Relocations
	E_cparhdr  WORD     // Size of header in paragraphs
	E_minalloc WORD     // Minimum extra paragraphs needed
	E_maxalloc WORD     // Maximum extra paragraphs needed
	E_ss       WORD     // Initial (relative) SS value
	E_sp       WORD     // Initial SP value
	E_csum     WORD     // Checksum
	E_ip       WORD     // Initial IP value
	E_cs       WORD     // Initial (relative) CS value
	E_lfarlc   WORD     // File address of relocation table
	E_ovno     WORD     // Overlay number
	E_res      [4]WORD  // Reserved words
	E_oemid    WORD     // OEM identifier (for E_oeminfo)
	E_oeminfo  WORD     // OEM information; E_oemid specific
	E_res2     [10]WORD // Reserved words
	E_lfanew   LONG     // File address of new exe header
}

type IMAGE_DOS_HEADER _IMAGE_DOS_HEADER

const (
	IMAGE_SIZEOF_SHORT_NAME = 8
)

type _IMAGE_SECTION_HEADER struct {
	Name [IMAGE_SIZEOF_SHORT_NAME]BYTE
	//union {
	//DWORD   PhysicalAddress;
	//DWORD   VirtualSize;
	//} Misc;
	Misc                 DWORD
	VirtualAddress       DWORD
	SizeOfRawData        DWORD
	PointerToRawData     DWORD
	PointerToRelocations DWORD
	PointerToLinenumbers DWORD
	NumberOfRelocations  WORD
	NumberOfLinenumbers  WORD
	Characteristics      DWORD
}

type IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       DWORD
	TimeDateStamp         DWORD
	MajorVersionv         WORD
	MinorVersion          WORD
	Name                  DWORD
	Base                  DWORD
	NumberOfFunctions     DWORD
	NumberOfNames         DWORD
	AddressOfFunctions    DWORD // RVA from base of image
	AddressOfNames        DWORD // RVA from base of image
	AddressOfNameOrdinals DWORD // RVA from base of image
}

