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

struct STORAGE_DEVICE_NUMBER
{
	DEVICE_TYPE DeviceType;
	ULONG       DeviceNumber;
	ULONG       PartitionNumber;
};

enum FILENAME = "trimcheck.bin";
enum FILESIZE = 1024; // Needs to be bigger than 512 to have a sector number

enum Conclusion { Enabled, Disabled, Unknown }

void run()
{
	writeln("SSD TRIM check - Written by Vladimir Panteleev");
	writeln();

	writefln("Generating random data block (%d bytes)...", FILESIZE);
	ubyte[FILESIZE] rndBuffer;
	foreach (ref b; rndBuffer)
		b = uniform!ubyte();
	writefln("  First 16 bytes: %(%02X %)", rndBuffer[0..16]);

	writeln("Writing data to ", absolutePath(FILENAME), "...");
	std.file.write(FILENAME, rndBuffer[]);

	writeln("Reopening file...");
	HANDLE hFile = CreateFileW(toUTF16z(FILENAME), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, null, OPEN_EXISTING, 0, null);
	wenforce(hFile != INVALID_HANDLE_VALUE, "CreateFileW failed");

	writeln("Querying file physical location...");
	STARTING_VCN_INPUT_BUFFER svib;
	svib.StartingVcn.QuadPart = 0;
	ubyte[1024] rpbBuf;
	PRETRIEVAL_POINTERS_BUFFER prpb = cast(PRETRIEVAL_POINTERS_BUFFER)rpbBuf;

	DWORD c;
	wenforce(DeviceIoControl(hFile, FSCTL_GET_RETRIEVAL_POINTERS, &svib, svib.sizeof, prpb, rpbBuf.sizeof, &c, null), "DeviceIoControl(FSCTL_GET_RETRIEVAL_POINTERS) failed");

	writefln("  %s has %d extent%s:", FILENAME, prpb.ExtentCount, prpb.ExtentCount==1?"":"s");
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

	auto drivePathBS = driveName(absolutePath(FILENAME)) ~ `\`;
	writefln("Querying %s sector size information...", drivePathBS);
	DWORD dwSectorsPerCluster, dwBytesPerSector, dwNumberOfFreeClusters, dwTotalNumberOfClusters;
	wenforce(GetDiskFreeSpaceW(toUTF16z(drivePathBS), &dwSectorsPerCluster, &dwBytesPerSector, &dwNumberOfFreeClusters, &dwTotalNumberOfClusters), "GetDiskFreeSpaceW failed");
	writefln("  %s has %d bytes per sector, and %d sectors per cluster.", drivePathBS, dwBytesPerSector, dwSectorsPerCluster);

	// BUG: This will break if a path element is a symlink or junction to another partition
	auto ntDrivePath = `\\.\` ~ driveName(absolutePath(FILENAME));
	writeln("Opening ", ntDrivePath, "...");
	HANDLE hDriveRead = CreateFileW(toUTF16z(ntDrivePath), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, null, OPEN_EXISTING, 0, null);
	wenforce(hDriveRead != INVALID_HANDLE_VALUE, "CreateFileW failed");
	scope(exit) CloseHandle(hDriveRead);

	LARGE_INTEGER uliOffset;
	uliOffset.QuadPart = prpb.Extents[0].Lcn.QuadPart * dwBytesPerSector * dwSectorsPerCluster;

	ubyte[FILESIZE] readBuffer;
	DWORD dwNumberOfBytesRead;

	void readBufferFromDisk()
	{
		writefln("  Seeking to position %d...", uliOffset.QuadPart);
		wenforce(SetFilePointer(hDriveRead, uliOffset.LowPart, &uliOffset.HighPart, FILE_BEGIN) != INVALID_SET_FILE_POINTER, "SetFilePointer failed");
		
		writefln("  Reading %d bytes...", FILESIZE);
		wenforce(ReadFile(hDriveRead, readBuffer.ptr, readBuffer.length, &dwNumberOfBytesRead, null), "ReadFile failed");
		enforce(dwNumberOfBytesRead == readBuffer.length, format("Read only %d out of %d bytes", dwNumberOfBytesRead, readBuffer.length));

		writefln("  First 16 bytes: %(%02X %)", readBuffer[0..16]);
	}

	writeln("Checking if file and raw volume data matches...");
	readBufferFromDisk();
	enforce(readBuffer[] == rndBuffer[], "Mismatch between file and raw volume data. Is the file under a symlink or directory junction?");

	writeln("Deleting file...");
	wenforce(DeleteFileW(toUTF16z(FILENAME)), "DeleteFile failed");

	ubyte[FILESIZE] nullBuffer;
	nullBuffer[] = 0;

	writeln("Re-checking raw volume data...");
	readBufferFromDisk();

	enforce(readBuffer[] == rndBuffer[] || readBuffer[] == nullBuffer[], format("Data is neither unchanged, nor zero. Something strange happened."));

	if (readBuffer[] == rndBuffer[])
	{
		writeln("Data unchanged.");
		writeln();
		writeln("CONCLUSION: TRIM appears to be NOT WORKING.");
	}
	else
	{
		writeln("Data is empty.");
		writeln();
		writeln("CONCLUSION: TRIM appears to be WORKING.");
	}
}

void main()
{
	try
		run();
	catch (Throwable e)
		writeln("Error: " ~ e.msg);	

	writeln("Press Enter to exit...");
	readln();
}
