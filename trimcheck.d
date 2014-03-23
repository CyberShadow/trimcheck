// Written in the D programming language

import std.algorithm;
import std.exception;
import std.file;
import std.path;
import std.random;
import std.stdio;
import std.string;
import std.utf;

// http://dsource.org/projects/bindings/wiki/WindowsApi
import win32.windows;
import win32.winioctl;

import ae.sys.windows;
import ae.utils.json;

alias max = std.algorithm.max;

struct STORAGE_DEVICE_NUMBER
{
	DEVICE_TYPE DeviceType;
	ULONG       DeviceNumber;
	ULONG       PartitionNumber;
}

struct STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR
{
	DWORD Version;
	DWORD Size;
	DWORD BytesPerCacheLine;
	DWORD BytesOffsetForCacheAlignment;
	DWORD BytesPerLogicalSector;
	DWORD BytesPerPhysicalSector;
	DWORD BytesOffsetForSectorAlignment;
}

alias DWORD STORAGE_PROPERTY_ID;
enum : STORAGE_PROPERTY_ID
{
	StorageDeviceProperty                  =  0,
	StorageAdapterProperty                 =  1,
	StorageDeviceIdProperty                =  2,
	StorageDeviceUniqueIdProperty          =  3,
	StorageDeviceWriteCacheProperty        =  4,
	StorageMiniportProperty                =  5,
	StorageAccessAlignmentProperty         =  6,
	StorageDeviceSeekPenaltyProperty       =  7,
	StorageDeviceTrimProperty              =  8,
	StorageDeviceWriteAggregationProperty  =  9,
	StorageDeviceDeviceTelemetryProperty   = 10, // 0xA
	StorageDeviceLBProvisioningProperty    = 11, // 0xB
	StorageDevicePowerProperty             = 12, // 0xC
	StorageDeviceCopyOffloadProperty       = 13, // 0xD
	StorageDeviceResiliencyProperty        = 14, // 0xE
}

alias DWORD STORAGE_QUERY_TYPE;
enum : STORAGE_QUERY_TYPE
{
	PropertyStandardQuery    = 0,
	PropertyExistsQuery      = 1,
	PropertyMaskQuery        = 2,
	PropertyQueryMaxDefined  = 3,
}

struct STORAGE_PROPERTY_QUERY
{
	STORAGE_PROPERTY_ID PropertyId;
	STORAGE_QUERY_TYPE  QueryType;
	BYTE                AdditionalParameters[1];
}

enum IOCTL_STORAGE_QUERY_PROPERTY = CTL_CODE_T!(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS);

extern(Windows) alias DWORD function(HANDLE hFile, LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags) GetFinalPathNameByHandleWFunc;

enum FILE_NAME_NORMALIZED = 0x0;

enum VOLUME_NAME_DOS  = 0x0;
enum VOLUME_NAME_GUID = 0x1;
enum VOLUME_NAME_NT   = 0x2;
enum VOLUME_NAME_NONE = 0x4;

enum DATAFILENAME = "trimcheck.bin";
enum SAVEFILENAME = "trimcheck-cont.json";

enum MB = 1024*1024;
enum PADDINGSIZE_MB = 32; // Size to pad our tested sector (in MB). Total size = PADDINGSIZE_MB*MB + DATASIZE + PADDINGSIZE_MB*MB.

void run()
{
	writeln("TRIM check v0.5 - Written by Vladimir Panteleev");
	writeln("https://github.com/CyberShadow/trimcheck");
	writeln();

	if (!SAVEFILENAME.exists)
	{
		create();

		// This causes weird behavior: the file never gets TRIMmed even if the program is closed and reopened.
		version(none)
		{
			int n;
			while (SAVEFILENAME.exists)
			{
				Sleep(1000);
				writefln("========================== %d seconds ==========================", ++n);
				verify();
			}
		}
	}
	else
		verify();
}

struct SaveData
{
	string ntDrivePath;
	ulong offset;
	ubyte[] rndBuffer;
}

ubyte[] readBufferFromDisk(string ntDrivePath, ulong offset, size_t dataSize)
{
	writefln("  Opening %s...", ntDrivePath);
	HANDLE hDriveRead = CreateFileW(toUTF16z(ntDrivePath), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, null, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, null);
	wenforce(hDriveRead != INVALID_HANDLE_VALUE, "CreateFileW failed");
	scope(exit) wenforce(CloseHandle(hDriveRead), "CloseHandle failed");

	writefln("  Seeking to position %d...", offset);
	LARGE_INTEGER uliOffset;
	uliOffset.QuadPart = offset;
	wenforce(SetFilePointer(hDriveRead, uliOffset.LowPart, &uliOffset.HighPart, FILE_BEGIN) != INVALID_SET_FILE_POINTER, "SetFilePointer failed");

	writefln("  Reading %d bytes...", dataSize);
	ubyte[] readBuffer = new ubyte[dataSize];
	DWORD dwNumberOfBytesRead;
	wenforce(ReadFile(hDriveRead, readBuffer.ptr, readBuffer.length, &dwNumberOfBytesRead, null), "ReadFile failed");
	enforce(dwNumberOfBytesRead == readBuffer.length, format("Read only %d out of %d bytes", dwNumberOfBytesRead, readBuffer.length));

	writefln("  First 16 bytes: %(%02X %)...", readBuffer[0..16]);

	return readBuffer;
}

void flushDiskBuffers(string ntDrivePath)
{
	writefln("Flushing buffers on %s...", ntDrivePath);

	writefln("  Opening %s...", ntDrivePath);
	HANDLE hDrive = CreateFileW(toUTF16z(ntDrivePath), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, null, OPEN_EXISTING, 0, null);
	wenforce(hDrive != INVALID_HANDLE_VALUE, "CreateFileW failed");
	scope(exit) wenforce(CloseHandle(hDrive), "CloseHandle failed");

	writeln("  Flushing buffers...");
	wenforce(FlushFileBuffers(hDrive), "FlushFileBuffers failed");
}

STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR detectSectorSize(string devName)
{
	writefln("  Obtaining sector size on %s...", devName);


	writefln("    Opening %s...", devName);
	HANDLE hFile = CreateFileW(toUTF16z(devName), STANDARD_RIGHTS_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
	wenforce(hFile != INVALID_HANDLE_VALUE, "CreateFileW failed");
	scope(exit) wenforce(CloseHandle(hFile), "CloseHandle failed");

	STORAGE_PROPERTY_QUERY query;
	query.QueryType  = PropertyStandardQuery;
	query.PropertyId = StorageAccessAlignmentProperty;

	writeln("    Querying storage alignment property...");
	DWORD dwBytes;
	STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR result;
	wenforce(DeviceIoControl(hFile, IOCTL_STORAGE_QUERY_PROPERTY, &query, query.sizeof, &result, result.sizeof, &dwBytes, null), "DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY) failed");

	writefln("      BytesPerCacheLine             = %d", result.BytesPerCacheLine            );
	writefln("      BytesOffsetForCacheAlignment  = %d", result.BytesOffsetForCacheAlignment );
	writefln("      BytesPerLogicalSector         = %d", result.BytesPerLogicalSector        );
	writefln("      BytesPerPhysicalSector        = %d", result.BytesPerPhysicalSector       );
	writefln("      BytesOffsetForSectorAlignment = %d", result.BytesOffsetForSectorAlignment);

	return result;
}

void writeBuf(HANDLE hFile, ubyte[] data)
{
	DWORD dwNumberOfBytesWritten;
	wenforce(WriteFile(hFile, data.ptr, data.length, &dwNumberOfBytesWritten, null), "WriteFile failed");
	enforce(data.length == dwNumberOfBytesWritten, format("Wrote only %d out of %d bytes", dwNumberOfBytesWritten, data.length));
}

/+
size_t getDataSize()
{
	writeln("Determining size of test data...");

	// BUG: This will break if a path element is a symlink or junction to another partition
	auto ntDrivePath = `\\.\` ~ driveName(absolutePath(DATAFILENAME));
	writefln("  Opening %s...", ntDrivePath);
	HANDLE hDrive = CreateFileW(toUTF16z(ntDrivePath), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, null, OPEN_EXISTING, 0, null);
	wenforce(hDrive != INVALID_HANDLE_VALUE, "CreateFileW failed");
	scope(exit) wenforce(CloseHandle(hDrive), "CloseHandle failed");

	writeln("  Querying drive information...");
	STORAGE_DEVICE_NUMBER sdn;
	DWORD c;
	wenforce(DeviceIoControl(hDrive, IOCTL_STORAGE_GET_DEVICE_NUMBER, null, 0, &sdn, sdn.sizeof, &c, null), "DeviceIoControl(IOCTL_STORAGE_GET_DEVICE_NUMBER) failed");

	// Device types are listed here: http://msdn.microsoft.com/en-us/library/windows/hardware/ff563821(v=vs.85).aspx
	writefln("    Drive is located on device %d (type 0x%08x), partition %d.", sdn.DeviceNumber, sdn.DeviceType, sdn.PartitionNumber);

	auto physicalDrivePath = format(`\\.\PhysicalDrive%d`, sdn.DeviceNumber);
	STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR saad = detectSectorSize(physicalDrivePath);

	auto dataSize = saad.BytesPerPhysicalSector;

	// Size needs to be bigger than 512 to have a sector number
	// (otherwise NTFS inlnes it into MFT or something).
	while (dataSize <= 512)
		dataSize *= 2;

	writefln("  Using data size of %d", dataSize);
	return dataSize;
}
+/

void create()
{
	writeln("USAGE: Place this program file on the same drive");
	writeln("you'd like to test TRIM on, and run it.");
	writeln();
	writefln("Press Enter to test drive %s...", driveName(absolutePath(DATAFILENAME)));
	readln();

	auto drivePathBS = driveName(absolutePath(DATAFILENAME)) ~ `\`;
	writefln("Querying %s disk space and sector size information...", drivePathBS);
	DWORD dwSectorsPerCluster, dwBytesPerSector, dwNumberOfFreeClusters, dwTotalNumberOfClusters;
	wenforce(GetDiskFreeSpaceW(toUTF16z(drivePathBS), &dwSectorsPerCluster, &dwBytesPerSector, &dwNumberOfFreeClusters, &dwTotalNumberOfClusters), "GetDiskFreeSpaceW failed");
	writefln("  %s has %d bytes per sector, and %d sectors per cluster.", drivePathBS, dwBytesPerSector, dwSectorsPerCluster);
	writefln("  %d out of %d sectors are free.", dwNumberOfFreeClusters, dwTotalNumberOfClusters);

	auto dataSize = max(16*1024, dwBytesPerSector * dwSectorsPerCluster);
	enforce(dataSize % (dwBytesPerSector * dwSectorsPerCluster)==0, format("Unsupported cluster size (%d*%d), please report this.", dwBytesPerSector, dwSectorsPerCluster));
	enforce(dwNumberOfFreeClusters * dwBytesPerSector * dwSectorsPerCluster > dataSize + PADDINGSIZE_MB * MB * 2, "Disk space is too low!");

	writefln("Generating random target data block (%d bytes)...", dataSize);
	auto rndBuffer = new ubyte[dataSize];
	foreach (ref b; rndBuffer)
		b = uniform!ubyte();
	writefln("  First 16 bytes: %(%02X %)...", rndBuffer[0..16]);

	writefln("Creating %s...", absolutePath(DATAFILENAME));
	HANDLE hFile = CreateFileW(toUTF16z(DATAFILENAME), GENERIC_READ | GENERIC_WRITE, 0, null, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING, null);
	wenforce(hFile != INVALID_HANDLE_VALUE, "CreateFileW failed");
	scope(exit) if (hFile) { wenforce(CloseHandle(hFile), "CloseHandle failed"); DeleteFileW(toUTF16z(DATAFILENAME)); }

	auto ntDrivePath = `\\.\` ~ driveName(absolutePath(DATAFILENAME));

	writeln("Querying file final paths...");
	GetFinalPathNameByHandleWFunc GetFinalPathNameByHandleW = cast(GetFinalPathNameByHandleWFunc) GetProcAddress(GetModuleHandle("kernel32.dll"), "GetFinalPathNameByHandleW");
	if (GetFinalPathNameByHandleW)
	{
		string getFinalPathName(DWORD dwKind)
		{
			static WCHAR[4096] buf;
			DWORD len = wenforce(GetFinalPathNameByHandleW(hFile, buf.ptr, buf.length, dwKind | FILE_NAME_NORMALIZED), "GetFinalPathNameByHandleW failed");
			return toUTF8(buf[0..len]);
		}

		string[int] paths;
		foreach (kind; [VOLUME_NAME_DOS, VOLUME_NAME_GUID, VOLUME_NAME_NT, VOLUME_NAME_NONE])
			paths[kind] = getFinalPathName(kind);

		writeln("  DOS  : ", paths[VOLUME_NAME_DOS ]);
		writeln("  GUID : ", paths[VOLUME_NAME_GUID]);
		writeln("  NT   : ", paths[VOLUME_NAME_NT  ]);
		writeln("  NONE : ", paths[VOLUME_NAME_NONE]);

		enforce(paths[VOLUME_NAME_DOS ].startsWith(`\\?\`), `DOS  path does not start with \\?\`);
		enforce(paths[VOLUME_NAME_GUID].startsWith(`\\?\`), `GUID path does not start with \\?\`);

		enforce(paths[VOLUME_NAME_DOS ].endsWith(paths[VOLUME_NAME_NONE]), "DOS  path does not end with NONE path");
		enforce(paths[VOLUME_NAME_GUID].endsWith(paths[VOLUME_NAME_NONE]), "GUID path does not end with NONE path");
		enforce(paths[VOLUME_NAME_NT  ].endsWith(paths[VOLUME_NAME_NONE]), "NT   path does not end with NONE path");

		enforce(icmp(ntDrivePath[4..$], paths[VOLUME_NAME_DOS][4..$-paths[VOLUME_NAME_NONE].length]) == 0,
			"Current directory seems to be located under a reparse point\nwhich points to another drive. Try placing the program file in the\nroot directory of the drive you wish to test.");
	}
	else
		writeln("WARNING: This system does not have GetFinalPathNameByHandle.\nSymlink detection skipped.");

	auto garbageData = new ubyte[MB];

	void write1MBGarbage()
	{
		foreach (ref b; garbageData)
			b = uniform!ubyte();
		writeBuf(hFile, garbageData);
	}

	writefln("Writing padding (%d bytes)...", PADDINGSIZE_MB*MB);
	foreach (n; 0..PADDINGSIZE_MB) write1MBGarbage();

	writefln("Writing data (%d bytes)...", dataSize);
	writeBuf(hFile, rndBuffer);

	writefln("Writing padding (%d bytes)...", PADDINGSIZE_MB*MB);
	foreach (n; 0..PADDINGSIZE_MB) write1MBGarbage();

	writeln("Flushing file...");
	wenforce(FlushFileBuffers(hFile), "FlushFileBuffers failed");

	writeln("Checking file size...");
	enforce(GetFileSize(hFile, null) == PADDINGSIZE_MB*MB + dataSize + PADDINGSIZE_MB*MB, "Unexpected file size");

	auto dataStartVCN = (PADDINGSIZE_MB*MB) / (dwBytesPerSector * dwSectorsPerCluster);
	auto dataEndVCN = dataStartVCN + (dataSize / (dwBytesPerSector * dwSectorsPerCluster));
	writefln("  Data is located at Virtual Cluster Numbers %d-%d within file.", dataStartVCN, dataEndVCN-1);

	writeln("Querying file physical location...");
	STARTING_VCN_INPUT_BUFFER svib;
	svib.StartingVcn.QuadPart = 0;
	auto rpbBuf = new ubyte[64*1024];
	PRETRIEVAL_POINTERS_BUFFER prpb = cast(PRETRIEVAL_POINTERS_BUFFER)rpbBuf;

	DWORD c;
	wenforce(DeviceIoControl(hFile, FSCTL_GET_RETRIEVAL_POINTERS, &svib, svib.sizeof, prpb, rpbBuf.length, &c, null), "DeviceIoControl(FSCTL_GET_RETRIEVAL_POINTERS) failed");

	writefln("  %s has %d extent%s:", DATAFILENAME, prpb.ExtentCount, prpb.ExtentCount==1?"":"s");
	ulong offset = 0;
	auto prevVcn = prpb.StartingVcn; // Should be 0
	foreach (n; 0..prpb.ExtentCount)
	{
		auto vcnStr = prevVcn.QuadPart == prpb.Extents()[n].NextVcn.QuadPart-1 ? format("Virtual cluster %d is", prevVcn.QuadPart) : format("Virtual clusters %d-%d are", prevVcn.QuadPart, prpb.Extents()[n].NextVcn.QuadPart-1);
		writefln("    Extent %d: %s located at LCN %d", n, vcnStr, prpb.Extents()[n].Lcn.QuadPart);

		auto startVCN = prevVcn.QuadPart;
		auto endVCN = prpb.Extents()[n].NextVcn.QuadPart;
		if (startVCN <= dataStartVCN && endVCN >= dataEndVCN)
		{
			writeln("      (this is the extent containing our data)");
			auto dataLCN = prpb.Extents()[n].Lcn.QuadPart + (dataStartVCN - startVCN);
			offset = dataLCN  * dwBytesPerSector * dwSectorsPerCluster;
		}

		prevVcn = prpb.Extents()[n].NextVcn;
	}

	foreach (n, extent; prpb.Extents()[0..prpb.ExtentCount])
		enforce(extent.Lcn.QuadPart>0, format("The Logical Cluster Number of extent %d is not set. Perhaps the file is compressed?", n));
	enforce(offset, "Could not find the extent of the data part of file.");

	writeln("Closing file.");
	wenforce(CloseHandle(hFile), "CloseHandle failed");
	hFile = null;

	writefln("Saving continuation data to %s...", absolutePath(SAVEFILENAME));
	std.file.write(SAVEFILENAME, toJson(SaveData(ntDrivePath, offset, rndBuffer[])));
	scope(failure) SAVEFILENAME[].remove();

	flushDiskBuffers(ntDrivePath);
/+
	writeln("Checking if file and raw volume data matches...");
	auto readBuffer = readBufferFromDisk(ntDrivePath, offset, dataSize);
	enforce(readBuffer == rndBuffer[], "Mismatch between file and raw volume data.\nIs the file under a symlink or directory junction?");
+/
	writeln("Deleting file...");
	wenforce(DeleteFileW(toUTF16z(DATAFILENAME)), "DeleteFile failed");

	flushDiskBuffers(ntDrivePath);
/+
	writeln("Re-checking raw volume data...");
	readBuffer = readBufferFromDisk(ntDrivePath, offset, dataSize);
	enforce(readBuffer == rndBuffer[], "Data mismatch (data was clobbered directly after deleting it).\nThis could indicate that TRIM occurred immediately,\nor TRIM-unrelated unusual file delete behavior.");
+/
	writeln();
	writeln("Test file created and deleted, and continuation data saved.");
	writeln("Do what needs to be done to activate the SSD's TRIM functionality,");
	writeln("and run this program again.");
	writeln("Usually, you just need to wait a bit (around 20 seconds).");
	writeln("Sometimes, a reboot is necessary.");
}

void verify()
{
	scope(failure) writefln("\nAn error has occurred during verification.\nTo start from scratch, delete %s.\n", SAVEFILENAME);

	writefln("Loading continuation data from %s...", absolutePath(SAVEFILENAME));
	auto saveData = jsonParse!SaveData(readText(SAVEFILENAME));
	writefln("  Drive path   :  %s", saveData.ntDrivePath);
	writefln("  Offset       :  %s", saveData.offset);
	writefln("  Random data  :  %(%02X %)...", saveData.rndBuffer[0..16]);
	writeln();

	auto dataSize = saveData.rndBuffer.length;

	writeln("Reading raw volume data...");
	auto readBuffer = readBufferFromDisk(saveData.ntDrivePath, saveData.offset, dataSize);
	auto nullBuffer0 = new ubyte[dataSize]; nullBuffer0[] = 0x00;
	auto nullBuffer1 = new ubyte[dataSize]; nullBuffer1[] = 0xFF;

	if (readBuffer == saveData.rndBuffer)
	{
		writeln("Data unchanged.");
		writeln();
		writeln("CONCLUSION: TRIM appears to be NOT WORKING (or has not kicked in yet).");
		writeln();
		writeln("You can re-run this program to test again with the same data block,");
		writefln("or delete %s to create a new test file.", SAVEFILENAME);
	}
	else
	if (readBuffer == nullBuffer0 || readBuffer == nullBuffer1)
	{
		writefln("Data is empty (filled with 0x%02X bytes).", readBuffer[0]);
		writeln();
		writeln("CONCLUSION: TRIM appears to be WORKING!");

		SAVEFILENAME[].remove();
	}
	else
	{
		writeln("Data is neither unchanged nor empty.");
		writeln("Possible cause: another program saved data to disk,");
		writeln("overwriting the sector containing our test data.");
		writeln();
		writeln("CONCLUSION: INDETERMINATE.");
		writefln("Re-run this program and wait less before verifying / try to\nminimize writes to drive %s.", saveData.ntDrivePath[$-2..$]);

		SAVEFILENAME[].remove();
	}
}

void main()
{
	try
		run();
	catch (Throwable e)
		writeln("Error: " ~ e.msg);

	writeln();
	writeln("Press Enter to exit...");
	readln();
}
