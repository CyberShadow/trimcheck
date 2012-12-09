import std.exception;
import std.file;
import std.path;
import std.random;
import std.stdio;
import std.string;
import std.utf;

import win32.windows;
import win32.winioctl;

import ae.sys.windows;
import ae.utils.json;

struct STORAGE_DEVICE_NUMBER
{
	DEVICE_TYPE DeviceType;
	ULONG       DeviceNumber;
	ULONG       PartitionNumber;
};

enum DATAFILENAME = "trimcheck.bin";
enum DATAFILESIZE = 1024; // Needs to be bigger than 512 to have a sector number

enum SAVEFILENAME = "trimcheck.json";

enum Conclusion { Enabled, Disabled, Unknown }

void run()
{
	writeln("SSD TRIM check - Written by Vladimir Panteleev");
	writeln();

	if (!SAVEFILENAME.exists)
		create();
	else
		verify();
}

struct SaveData
{
	string ntDrivePath;
	ulong offset;
	ubyte[] rndBuffer;
}

ubyte[] readBufferFromDisk(string ntDrivePath, ulong offset)
{
	writefln("  Opening %s...", ntDrivePath);
	HANDLE hDriveRead = CreateFileW(toUTF16z(ntDrivePath), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, null, OPEN_EXISTING, 0, null);
	wenforce(hDriveRead != INVALID_HANDLE_VALUE, "CreateFileW failed");
	scope(exit) CloseHandle(hDriveRead);

	writefln("  Seeking to position %d...", offset);
	LARGE_INTEGER uliOffset;
	uliOffset.QuadPart = offset;
	wenforce(SetFilePointer(hDriveRead, uliOffset.LowPart, &uliOffset.HighPart, FILE_BEGIN) != INVALID_SET_FILE_POINTER, "SetFilePointer failed");

	writefln("  Reading %d bytes...", DATAFILESIZE);
	ubyte[] readBuffer = new ubyte[DATAFILESIZE];
	DWORD dwNumberOfBytesRead;
	wenforce(ReadFile(hDriveRead, readBuffer.ptr, readBuffer.length, &dwNumberOfBytesRead, null), "ReadFile failed");
	enforce(dwNumberOfBytesRead == readBuffer.length, format("Read only %d out of %d bytes", dwNumberOfBytesRead, readBuffer.length));

	writefln("  First 16 bytes: %(%02X %)", readBuffer[0..16]);

	return readBuffer;
}

void create()
{
	writefln("Generating random data block (%d bytes)...", DATAFILESIZE);
	ubyte[DATAFILESIZE] rndBuffer;
	foreach (ref b; rndBuffer)
		b = uniform!ubyte();
	writefln("  First 16 bytes: %(%02X %)", rndBuffer[0..16]);

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

	writeln("Checking if file and raw volume data matches...");
	auto readBuffer = readBufferFromDisk(ntDrivePath, offset);
	enforce(readBuffer == rndBuffer[], "Mismatch between file and raw volume data. Is the file under a symlink or directory junction?");

	writeln("Deleting file...");
	wenforce(DeleteFileW(toUTF16z(DATAFILENAME)), "DeleteFile failed");

	writeln("Re-checking raw volume data...");
	readBuffer = readBufferFromDisk(ntDrivePath, offset);

	enforce(readBuffer == rndBuffer[], "Data mismatch (data was clobbered directly after deleting it).\nThis could indicate that TRIM occurred immediately,\nor TRIM-unrelated unusual file delete behavior.");

	writeln();
	writeln("Test file created and deleted, and continuation data saved.");
	writeln("Do what needs to be done to activate the SSD's TRIM functionality,");
	writeln("and run this program again.");
	writeln("On some drives you just need to wait a bit; on others, a reboot is necessary.");
}

void verify()
{
	writefln("Loading continuation data from %s...", absolutePath(SAVEFILENAME));
	auto saveData = jsonParse!SaveData(readText(SAVEFILENAME));
	scope(success) SAVEFILENAME[].remove();
	writefln("  Drive path   :  %s", saveData.ntDrivePath);
	writefln("  Offset       :  %s", saveData.offset);
	writefln("  Random data  :  %(%02X %)", saveData.rndBuffer[0..16], "...");
	writeln();

	writeln("Reading raw volume data...");
	auto readBuffer = readBufferFromDisk(saveData.ntDrivePath, saveData.offset);

	ubyte[DATAFILESIZE] nullBuffer;
	nullBuffer[] = 0;

	if (readBuffer == saveData.rndBuffer)
	{
		writeln("Data unchanged.");
		writeln();
		writeln("CONCLUSION: TRIM appears to be NOT WORKING.");
	}
	else
	if (readBuffer == nullBuffer)
	{
		writeln("Data is empty.");
		writeln();
		writeln("CONCLUSION: TRIM appears to be WORKING.");
	}
	else
	{
		writeln("Data is neither unchanged nor empty.");
		writeln("Possible cause: another program saved data to disk,");
		writeln("overwriting the sector containing our test data.");
		writeln();
		writeln("CONCLUSION: INDETERMINATE. Re-run this program and try to minimize I/O.");
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
