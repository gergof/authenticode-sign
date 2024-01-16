enum DataDirectoryType {
	ExportTable = 0,
	ImportTable = 1,
	ResourceTable = 2,
	ExceptionTable = 3,
	CertificateTable = 4,
	BaseRelocationTable = 5,
	Debug = 6,
	Architecture = 7,
	GlobalPointer = 8,
	ThreadLocalStorageTable = 9,
	LoadConfigTable = 10,
	BoundImportTable = 11,
	ImportAddressTable = 12,
	DelayLoadImportTable = 13,
	ClrRuntimeHeader = 14
}

export default DataDirectoryType;
