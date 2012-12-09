// Written in the D programming language

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

enum DATAFILENAME = "trimcheck.bin";
enum SAVEFILENAME = "trimcheck-cont.json";

void run()
{
	writeln("TRIM check - Written by Vladimir Panteleev");
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
	scope(exit) CloseHandle(hDriveRead);

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
	scope(exit) CloseHandle(hDrive);

	writeln("  Flushing buffers...");
	FlushFileBuffers(hDrive);
}

STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR detectSectorSize(string devName)
{
	writefln("  Obtaining sector size on %s...", devName);


	writefln("    Opening %s...", devName);
	HANDLE hFile = CreateFileW(toUTF16z(devName), STANDARD_RIGHTS_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
	wenforce(hFile != INVALID_HANDLE_VALUE, "CreateFileW failed");
	scope(exit) CloseHandle(hFile);

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

size_t getDataSize()
{
	writeln("Determining size of test data...");

	// BUG: This will break if a path element is a symlink or junction to another partition
	auto ntDrivePath = `\\.\` ~ driveName(absolutePath(DATAFILENAME));
	writefln("  Opening %s...", ntDrivePath);
	HANDLE hDrive = CreateFileW(toUTF16z(ntDrivePath), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, null, OPEN_EXISTING, 0, null);
	wenforce(hDrive != INVALID_HANDLE_VALUE, "CreateFileW failed");
	scope(exit) CloseHandle(hDrive);

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

void create()
{
	writeln("USAGE: Place this program file on the same drive");
	writeln("you'd like to test TRIM on, and run it.");
	writeln();
	writeln("Press Enter to continue...");
	readln();

	auto dataSize = getDataSize();

	writefln("Generating random data block (%d bytes)...", dataSize);
	auto rndBuffer = new ubyte[dataSize];
	foreach (ref b; rndBuffer)
		b = uniform!ubyte();
	writefln("  First 16 bytes: %(%02X %)...", rndBuffer[0..16]);

	writefln("Writing data to %s...", absolutePath(DATAFILENAME));
	std.file.write(DATAFILENAME, rndBuffer[]);

	writeln("Reopening file...");
	HANDLE hFile = CreateFileW(toUTF16z(DATAFILENAME), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, null, OPEN_EXISTING, 0, null);
	wenforce(hFile != INVALID_HANDLE_VALUE, "CreateFileW failed");

	writeln("Querying file physical location...");
	STARTING_VCN_INPUT_BUFFER svib;
	svib.StartingVcn.QuadPart = 0;
	ubyte[1024] rpbBuf;
	PRETRIEVAL_POINTERS_BUFFER prpb = cast(PRETRIEVAL_POINTERS_BUFFER)rpbBuf;

	DWORD c;
	wenforce(DeviceIoControl(hFile, FSCTL_GET_RETRIEVAL_POINTERS, &svib, svib.sizeof, prpb, rpbBuf.sizeof, &c, null), "DeviceIoControl(FSCTL_GET_RETRIEVAL_POINTERS) failed");

	writefln("  %s has %d extent%s:", DATAFILENAME, prpb.ExtentCount, prpb.ExtentCount==1?"":"s");
	auto prevVcn = prpb.StartingVcn; // Should be 0
	foreach (n; 0..prpb.ExtentCount)
	{
		auto vcnStr = prevVcn.QuadPart == prpb.Extents[n].NextVcn.QuadPart-1 ? format("Virtual cluster %d is", prevVcn.QuadPart) : format("Virtual clusters %d-%d are", prevVcn.QuadPart, prpb.Extents[n].NextVcn.QuadPart-1);
		writefln("    Extent %d: %s located at Logical Cluster Number %d", n, vcnStr, prpb.Extents[n].Lcn.QuadPart);
		prevVcn = prpb.Extents[n].NextVcn;
	}

	enforce(prpb.ExtentCount==1, "The file doesn't have exactly 1 extent. Cluster size too small / file size too big?");
	enforce(prpb.Extents[0].Lcn.QuadPart>0, "The Logical Cluster Number is not set. Perhaps the file is compressed?");
	CloseHandle(hFile);

	auto drivePathBS = driveName(absolutePath(DATAFILENAME)) ~ `\`;
	writefln("Querying %s sector size information...", drivePathBS);
	DWORD dwSectorsPerCluster, dwBytesPerSector, dwNumberOfFreeClusters, dwTotalNumberOfClusters;
	wenforce(GetDiskFreeSpaceW(toUTF16z(drivePathBS), &dwSectorsPerCluster, &dwBytesPerSector, &dwNumberOfFreeClusters, &dwTotalNumberOfClusters), "GetDiskFreeSpaceW failed");
	writefln("  %s has %d bytes per sector, and %d sectors per cluster.", drivePathBS, dwBytesPerSector, dwSectorsPerCluster);

	// BUG: This will break if a path element is a symlink or junction to another partition
	auto ntDrivePath = `\\.\` ~ driveName(absolutePath(DATAFILENAME));
	ulong offset = prpb.Extents[0].Lcn.QuadPart * dwBytesPerSector * dwSectorsPerCluster;

	writefln("Saving continuation data to %s...", absolutePath(SAVEFILENAME));
	std.file.write(SAVEFILENAME, toJson(SaveData(ntDrivePath, offset, rndBuffer[])));
	scope(failure) SAVEFILENAME[].remove();

	flushDiskBuffers(ntDrivePath);

	writeln("Checking if file and raw volume data matches...");
	auto readBuffer = readBufferFromDisk(ntDrivePath, offset, dataSize);
	enforce(readBuffer == rndBuffer[], "Mismatch between file and raw volume data.\nIs the file under a symlink or directory junction?");

	writeln("Deleting file...");
	wenforce(DeleteFileW(toUTF16z(DATAFILENAME)), "DeleteFile failed");

	flushDiskBuffers(ntDrivePath);

	writeln("Re-checking raw volume data...");
	readBuffer = readBufferFromDisk(ntDrivePath, offset, dataSize);

	enforce(readBuffer == rndBuffer[], "Data mismatch (data was clobbered directly after deleting it).\nThis could indicate that TRIM occurred immediately,\nor TRIM-unrelated unusual file delete behavior.");

	writeln();
	writeln("Test file created and deleted, and continuation data saved.");
	writeln("Do what needs to be done to activate the SSD's TRIM functionality,");
	writeln("and run this program again.");
	writeln("Usually, you just need to wait a bit (around 15 seconds).");
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

	auto dataSize = getDataSize();

	writeln("Reading raw volume data...");
	auto readBuffer = readBufferFromDisk(saveData.ntDrivePath, saveData.offset, dataSize);
	auto nullBuffer = new ubyte[dataSize];

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
	if (readBuffer == nullBuffer)
	{
		writeln("Data is empty.");
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
