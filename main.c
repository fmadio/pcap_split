//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2017, fmad engineering llc 
//
// TB scale pcap splitter 
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <linux/sched.h>

#include "fTypes.h"

//---------------------------------------------------------------------------------------------

#define SPLIT_MODE_BYTE					1
#define SPLIT_MODE_TIME					2

#define FILENAME_EPOCH_SEC				1
#define FILENAME_EPOCH_SEC_STARTEND		2
#define FILENAME_EPOCH_MSEC				3
#define FILENAME_EPOCH_USEC				4
#define FILENAME_EPOCH_NSEC				5
#define FILENAME_TSTR_HHMM				6
#define FILENAME_TSTR_HHMMSS			7
#define FILENAME_TSTR_HHMMSS_NS			8

#define OUTPUT_MODE_CAT					1					// cat > blah.pcap
#define OUTPUT_MODE_RCLONE				2					// rclone rcat 
	
//---------------------------------------------------------------------------------------------
// pcap headers

#define PCAPHEADER_MAGIC_NANO		0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC		0xa1b2c3d4
#define PCAPHEADER_MAJOR			2
#define PCAPHEADER_MINOR			4
#define PCAPHEADER_LINK_ETHERNET	1
#define PCAPHEADER_LINK_ERF			197	

typedef struct
{
	u32				Sec;				// time stamp sec since epoch 
	u32				NSec;				// nsec fraction since epoch

	u32				LengthCapture;		// captured length, inc trailing / aligned data
	u32				Length;				// length on the wire

} __attribute__((packed)) PCAPPacket_t;

// per file header

typedef struct
{

	u32				Magic;
	u16				Major;
	u16				Minor;
	u32				TimeZone;
	u32				SigFlag;
	u32				SnapLen;
	u32				Link;

} __attribute__((packed)) PCAPHeader_t;

double TSC2Nano = 0;
static u8 s_FileNameSuffix[4096];			// suffix to apply to output filename

//-------------------------------------------------------------------------------------------------

static void Help(void)
{
	printf("\n");
	printf("fmadio 10G/40G/100G Packet Capture Systems (https://fmad.io)\n");
	printf("(%s)\n", __TIMESTAMP__);
	printf("\n");
	printf("pcap_split -o <output base> -s <split type> \n");
	printf("\n");
	printf("NOTE: Input PCAP`s are always read from STDIN\n");
	printf("\n");
	printf("-v                          : verbose output\n");
	printf("--split-byte  <byte count>  : split by bytes\n");
	printf("--split-time  <nanoseconds> : split by time\n");
	printf("\n");
	printf("--filename-epoch-sec          : output epoch sec  filename\n");
	printf("--filename-epoch-sec-startend : output epoch sec start/end filename\n");
	printf("--filename-epoch-msec         : output epoch msec filename\n");
	printf("--filename-epoch-usec         : output epoch usec filename\n");
	printf("--filename-epoch-nsec         : output epoch nsec filename\n");

	printf("--filename-tstr-HHMM       : output time string filename (Hour Min)\n");
	printf("--filename-tstr-HHMMSS     : output time string filename (Hour Min Sec)\n");
	printf("--filename-tstr-HHMMSS_NS  : output time string filename (Hour Min Sec Nanos)\n");
	printf("\n");
	printf("--filename-suffix          : filename suffix (default .pcap)\n");
	printf("\n");
	printf("--pipe-cmd                 : introduce a pipe command before final output\n");
	printf("--rclone                   : endpoint is an rclone endpoint\n");
	printf("\n");
	printf("\n");
	printf("example: split every 100GB\n");
	printf("$ cat my_big_capture.pcap | pcap_split -o my_big_capture_ --split-byte 100e9\n");
	printf("\n");

	printf("example: split every 1min\n");
	printf("$ cat my_big_capture.pcap | pcap_split -o my_big_capture_ --split-time 60e9\n");
	printf("\n");
	printf("example: split compress pcap every 100GB\n");
	printf("$ gzip -d -c my_big_capture.pcap.gz | pcap_split -o my_big_capture_ --split-byte 100e9\n");
	printf("\n");
}

//-------------------------------------------------------------------------------------------------
// various different naming formats 
static void GenerateFileName(u32 Mode, u8* FileName, u8* BaseName, u64 TS, u64 TSLast)
{
	switch (Mode)
	{
	case FILENAME_EPOCH_SEC:
		sprintf(FileName, "%s%lli%s", BaseName, (u64)(TS / 1e9), s_FileNameSuffix); 
		break;
	case FILENAME_EPOCH_SEC_STARTEND:
		sprintf(FileName, "%s%lli-%lli%s", BaseName, (u64)(TSLast / 1e9), (u64)(TS / 1e9), s_FileNameSuffix); 
		break;
	case FILENAME_EPOCH_MSEC:
		sprintf(FileName, "%s%lli%s", BaseName, (u64)(TS/1e6), s_FileNameSuffix);
		break;

	case FILENAME_EPOCH_USEC:
		sprintf(FileName, "%s%lli%s", BaseName, (u64)(TS/1e3), s_FileNameSuffix);
		break;

	case FILENAME_EPOCH_NSEC:
		sprintf(FileName, "%s%lli%s", BaseName, TS, s_FileNameSuffix);
		break;

	case FILENAME_TSTR_HHMM:
		{
			clock_date_t c	= ns2clock(TS);

			u64 nsec = TS % (u64)1e9;

			u64 msec = (nsec / 1e6); 
			nsec = nsec - msec * 1e6;

			u64 usec = (nsec / 1e3); 
			nsec = nsec - usec * 1e3;

			sprintf(FileName, "%s_%04i%02i%02i_%02i%02i%s", BaseName, c.year, c.month, c.day, c.hour, c.min, s_FileNameSuffix);
		}
		break;

	case FILENAME_TSTR_HHMMSS:
		{
			clock_date_t c	= ns2clock(TS);

			u64 nsec = TS % (u64)1e9;

			u64 msec = (nsec / 1e6); 
			nsec = nsec - msec * 1e6;

			u64 usec = (nsec / 1e3); 
			nsec = nsec - usec * 1e3;

			sprintf(FileName, "%s_%04i%02i%02i_%02i%02i%02i%s", BaseName, c.year, c.month, c.day, c.hour, c.min, c.sec, s_FileNameSuffix); 
		}
		break;

	case FILENAME_TSTR_HHMMSS_NS:
		{
			clock_date_t c	= ns2clock(TS);

			u64 nsec = TS % (u64)1e9;

			u64 msec = (nsec / 1e6); 
			nsec = nsec - msec * 1e6;

			u64 usec = (nsec / 1e3); 
			nsec = nsec - usec * 1e3;

			sprintf(FileName, "%s_%04i%02i%02i_%02i%02i%02i.%03lli.%03lli.%03lli%s", BaseName, c.year, c.month, c.day, c.hour, c.min, c.sec, msec, usec, nsec, s_FileNameSuffix); 
		}
		break;

	default:
		fprintf(stderr, "unknown filename mode\n");
		assert(false);
		break;
	}
}

//-------------------------------------------------------------------------------------------------
// generate pipe command based on config 
static void GeneratePipeCmd(u8* Cmd, u32 Mode, u8* PipeCmd, u8* FileName)
{
	switch (Mode)
	{
	case OUTPUT_MODE_CAT:
		sprintf(Cmd, "%s > %s", PipeCmd, FileName);
		break;

	case OUTPUT_MODE_RCLONE:
		sprintf(Cmd, "%s | rclone --config=/opt/fmadio/etc/rclone.conf --ignore-checksum rcat %s", PipeCmd, FileName);
		break;
	}
}

//-------------------------------------------------------------------------------------------------
// rename file 
static void RenameFile(u32 Mode, u8* FileNamePending, u8* FileName)
{
	switch (Mode)
	{
	case OUTPUT_MODE_CAT:
		rename(FileNamePending, FileName);
		break;

	case OUTPUT_MODE_RCLONE:
		{
			u8 Cmd[4096];
			sprintf(Cmd, "rclone --config=/opt/fmadio/etc/rclone.conf moveto %s %s", FileNamePending, FileName);
			printf("Cmd [%s]\n", Cmd);
			system(Cmd);
		}
		break;
	}
}

//-------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	char* OutFileName = NULL;

	u64 TargetByte 	= 0;
	u64 TargetTime 	= 0;

	u32 SplitMode		= 0;
	u32 FileNameMode	= 0;

	// default do nothing output
	u8 PipeCmd[4096];		
	strcpy(PipeCmd, "cat");

	// default .pcap raw
	strcpy(s_FileNameSuffix, ".pcap");

	// output to cat by default 
	u32 OutputMode  = OUTPUT_MODE_CAT;

	fprintf(stderr, "args\n");
	for (int i=1; i < argc; i++)
	{
		fprintf(stderr, "  %s\n", argv[i]);
	}

	for (int i=1; i < argc; i++)
	{
		fprintf(stderr, "%s\n", argv[i]);
		if (strcmp(argv[i], "--help") == 0)
		{
			Help();
			return 0;
		}
		// dummy uid for analytics scripts
		else if (strcmp(argv[i], "--uid") == 0)
		{
			u8* UID = argv[i+1];
			i++;
			fprintf(stderr, "UID [%s]\n", UID);
		}
		else if (strcmp(argv[i], "-o") == 0)
		{
			OutFileName = argv[i+1];
			i++;
		}
		else if (strcmp(argv[i], "--split-byte") == 0)
		{
			SplitMode = SPLIT_MODE_BYTE; 

			TargetByte = atof(argv[i+1]);
			i++;

			fprintf(stderr, "Split Every %lli Bytes %.3f GByte\n", TargetByte, TargetByte / (double)kGB(1));
		}
		else if (strcmp(argv[i], "--split-time") == 0)
		{
			SplitMode = SPLIT_MODE_TIME; 

			TargetTime = atof(argv[i+1]);
			i++;

			fprintf(stderr, "Split Every %lli Sec\n", TargetTime / 1e9);
		}
		else if (strcmp(argv[i], "--filename-epoch-sec") == 0)
		{
			fprintf(stderr, "Filename EPOCH Sec\n");
			FileNameMode	= FILENAME_EPOCH_SEC;
		}
		else if (strcmp(argv[i], "--filename-epoch-sec-startend") == 0)
		{
			fprintf(stderr, "Filename EPOCH Sec Start/End\n");
			FileNameMode	= FILENAME_EPOCH_SEC_STARTEND;
		}
		else if (strcmp(argv[i], "--filename-epoch-msec") == 0)
		{
			fprintf(stderr, "Filename EPOCH MSec\n");
			FileNameMode	= FILENAME_EPOCH_MSEC;
		}
		else if (strcmp(argv[i], "--filename-epoch-usec") == 0)
		{
			fprintf(stderr, "Filename EPOCH Micro Sec\n");
			FileNameMode	= FILENAME_EPOCH_USEC;
		}
		else if (strcmp(argv[i], "--filename-epoch-nsec") == 0)
		{
			fprintf(stderr, "Filename EPOCH nano Sec\n");
			FileNameMode	= FILENAME_EPOCH_NSEC;
		}
		else if (strcmp(argv[i], "--filename-tstr-HHMM") == 0)
		{
			fprintf(stderr, "Filename TimeString HHMM\n");
			FileNameMode	= FILENAME_TSTR_HHMM;
		}
		else if (strcmp(argv[i], "--filename-tstr-HHMMSS") == 0)
		{
			fprintf(stderr, "Filename TimeString HHMMSS\n");
			FileNameMode	= FILENAME_TSTR_HHMMSS;
		}
		else if (strcmp(argv[i], "--filename-tstr-HHMMSS_NS") == 0)
		{
			fprintf(stderr, "Filename TimeString HHMMSS Nano\n");
			FileNameMode	= FILENAME_TSTR_HHMMSS_NS;
		}
		else if (strcmp(argv[i], "--pipe-cmd") == 0)
		{
			strncpy(PipeCmd, argv[i+1], sizeof(PipeCmd));	
			fprintf(stderr, "pipe cmd [%s]\n", PipeCmd);
			i++;
		}
		else if (strcmp(argv[i], "--filename-suffix") == 0)
		{
			strncpy(s_FileNameSuffix, argv[i+1], sizeof(s_FileNameSuffix));	
			fprintf(stderr, "Filename Suffix [%s]\n", s_FileNameSuffix);
			i++;
		}
		else if (strcmp(argv[i], "--rclone") == 0)
		{
			OutputMode = OUTPUT_MODE_RCLONE;
			fprintf(stderr, "Output Mode RClone\n");
		}

	}

	// check for valid config
	switch (SplitMode)
	{
	case SPLIT_MODE_BYTE:
	case SPLIT_MODE_TIME:
		break;

	defualt:
		fprintf(stderr, "invalid config\n");
		Help();
		return 0;
	}

	switch (FileNameMode)
	{
	case FILENAME_EPOCH_SEC:
	case FILENAME_EPOCH_SEC_STARTEND:
	case FILENAME_EPOCH_MSEC:
	case FILENAME_EPOCH_USEC:
	case FILENAME_EPOCH_NSEC:
	case FILENAME_TSTR_HHMM:
	case FILENAME_TSTR_HHMMSS:
	case FILENAME_TSTR_HHMMSS_NS:
		break;

	default:
		fprintf(stderr, "invalid filename mode\n");
		break;
	}

	FILE* FIn = stdin; 
	assert(FIn != NULL);

	// read header
	PCAPHeader_t HeaderMaster;
	int rlen = fread(&HeaderMaster, 1, sizeof(HeaderMaster), FIn);
	if (rlen != sizeof(HeaderMaster))
	{
		printf("Failed to read pcap header\n");
		return 0;
	}

	u64 TScale = 0;
	switch (HeaderMaster.Magic)
	{
	case PCAPHEADER_MAGIC_NANO: printf("PCAP Nano\n"); TScale = 1;    break;
	case PCAPHEADER_MAGIC_USEC: printf("PCAP Micro\n"); TScale = 1000; break;
	}

	u64 StartTS					= clock_ns();
	u64 TotalByte				= 0;
	u64 TotalPkt				= 0;

	u64 SplitByte	 			= -1;	
	FILE* OutFile 				= NULL;

	u64 LastTS					= 0;
	u64 SplitTS					= 0;
	u64 LastSplitTS				= 0;

	u8* 			Pkt			= malloc(1024*1024);	
	PCAPPacket_t*	PktHeader	= (PCAPPacket_t*)Pkt;

	u8 FileName[1024];			// filename of the final output
	u8 FileNamePending[1024];	// filename of the currently active write

	while (!feof(FIn))
	{
		// header 
		int rlen = fread(PktHeader, 1, sizeof(PCAPPacket_t), FIn);
		if (rlen != sizeof(PCAPPacket_t)) break;

		// validate size
		if ((PktHeader->LengthCapture == 0) || (PktHeader->LengthCapture > 128*1024)) 
		{
			printf("Invalid packet length: %i\n", PktHeader->LengthCapture);
			break;
		}

		// payload
		rlen = fread(PktHeader + 1, 1, PktHeader->LengthCapture, FIn);
		if (rlen != PktHeader->LengthCapture)
		{
			printf("payload read fail %i expect %i\n", rlen, PktHeader->LengthCapture);
			break;
		}

		u64 TS = (u64)PktHeader->Sec * 1e9 + (u64)PktHeader->NSec * TScale;

		// set the first time
		if (LastSplitTS == 0) LastSplitTS = TS;

		// split mode
		bool NewSplit = false;
		switch (SplitMode)
		{
		case SPLIT_MODE_BYTE:

			// next split ? 
			if (SplitByte > TargetByte)
			{
				// close file and rename
				if (OutFile)
				{
					fclose(OutFile);

					// rename to file name 
					RenameFile(OutputMode, FileNamePending, FileName);
				}

				GenerateFileName(FileNameMode, FileName, OutFileName, TS, LastSplitTS);
				sprintf(FileNamePending, "%s.pending", FileName);

				u8 Cmd[4095];
				GeneratePipeCmd(Cmd, OutputMode, PipeCmd, FileNamePending);

				printf("[%s]\n", Cmd);
				OutFile 		= popen(Cmd, "w");
				if (!OutFile)
				{
					printf("OutputFilename is invalid [%s] %i %s\n", FileName, errno, strerror(errno));
					break;	
				}

				fwrite(&HeaderMaster, 1, sizeof(HeaderMaster), OutFile);	
				fflush(OutFile);

				LastSplitTS	= TS;

				SplitByte 	= 0;
				NewSplit 	= true;
			}
			break;

		case SPLIT_MODE_TIME:
			{
				s64 dTS = TS - SplitTS;
				if (dTS > TargetTime) 
				{
					u64 _SplitTS = SplitTS;

					SplitTS = (TS / TargetTime);
					SplitTS *= TargetTime;
					//fprintf(stderr, "split time: %lli\n", SplitTS);

					// create null PCAPs for anything missing 

					// close file and rename
					if (OutFile)
					{
						fclose(OutFile);

						// rename to file name 
						RenameFile(OutputMode, FileNamePending, FileName);
					}

					GenerateFileName(FileNameMode, FileName, OutFileName, SplitTS + TargetTime, SplitTS);
					sprintf(FileNamePending, "%s.pending", FileName);

					//OutFile 		= fopen(FileNamePending, "wb");

					u8 Cmd[4095];
					GeneratePipeCmd(Cmd, OutputMode, PipeCmd, FileNamePending);
					printf("[%s]\n", Cmd);
					OutFile 		= popen(Cmd, "w");
					if (!OutFile)
					{
						printf("OutputFilename is invalid [%s]\n", FileName);
						break;	
					}	
					fwrite(&HeaderMaster, 1, sizeof(HeaderMaster), OutFile);	

					LastSplitTS	= _SplitTS;

					SplitByte 	= 0;
					NewSplit 	= true;
				}
			}
			break;
		}

		// write output
		int wlen = fwrite(Pkt, 1, sizeof(PCAPPacket_t) + PktHeader->LengthCapture, OutFile);
		if (wlen != sizeof(PCAPPacket_t) + PktHeader->LengthCapture)
		{
			printf("write failure. possibly out of disk space\n");
			break;
		}

		LastTS = TS;

		SplitByte += sizeof(PCAPPacket_t) + PktHeader->LengthCapture;
		TotalByte += sizeof(PCAPPacket_t) + PktHeader->LengthCapture;
		TotalPkt  += 1; 

		if (NewSplit)
		{
			u8 TimeStr[1024];
			clock_date_t c	= ns2clock(TS);
			sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);

			double dT = (clock_ns() - StartTS) / 1e9;
			double Bps = (TotalByte * 8.0) / dT; 
			printf("[%.3f H][%s] %s : Total Bytes %.3f GB Speed: %.3fGbps : New Split\n", dT / (60*60), TimeStr, FileName, TotalByte / 1e9, Bps / 1e9);
			fflush(stdout);
			fflush(stderr);
		}

		if ((TotalPkt % (u64)1e6) == 0)
		{
			u8 TimeStr[1024];
			clock_date_t c	= ns2clock(LastTS);
			sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);

			double dT = (clock_ns() - StartTS) / 1e9;
			double Bps = (TotalByte * 8.0) / dT; 
			printf("[%.3f H][%s] %s : Total Bytes %.3f GB Speed: %.3fGbps\n", dT / (60*60), TimeStr, FileName, TotalByte / 1e9, Bps / 1e9);
			fflush(stdout);
			fflush(stderr);
		}
	}

	// final close and re-name
	fclose(OutFile);
	RenameFile(OutputMode, FileNamePending, FileName);

	printf("Complete\n");

	return 0;
}
