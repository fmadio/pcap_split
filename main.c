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
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <linux/sched.h>

#include "fTypes.h"

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

//-------------------------------------------------------------------------------------------------

static void Help(void)
{
	printf("pcap_split -o <output base> -s <split type> \n");
	printf("\n");
	printf("NOTE: Input PCAP`s are always read from STDIN\n");
	printf("\n");
	printf("-v                         : verbose output\n");
	printf("--split-byte  <byte count> : split by bytes\n");
	printf("\n");
	printf("example: split every 100GB\n");
	printf("$ cat my_big_capture.pcap | pcap_split -o my_big_capture_ --split-byte 100e9\n");
	printf("\n");
	printf("example: split compress pcap every 100GB\n");
	printf("$ gzip -d -c my_big_capture.pcap.gz | pcap_split -o my_big_capture_ --split-byte 100e9\n");
	printf("\n");
}

//-------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	char* OutFileName = NULL;

	u64 TargetByte = 0;

	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "--help") == 0)
		{
			Help();
			return 0;
		}
		else if (strcmp(argv[i], "-o") == 0)
		{
			OutFileName = argv[i+1];
			i++;
		}
		else if (strcmp(argv[i], "--split-byte") == 0)
		{
			TargetByte = atof(argv[i+1]);
			i++;

			fprintf(stderr, "Split Every %lli Bytes %.3f GByte\n", TargetByte, TargetByte / (double)kGB(1));
		}
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

	u8* 			Pkt			= malloc(1024*1024);	
	PCAPPacket_t*	PktHeader	= (PCAPPacket_t*)Pkt;
	u8 FileName[1024];	

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

		LastTS = (u64)PktHeader->Sec * 1e9 + (u64)PktHeader->NSec * TScale;

		// next split ? 
		if (SplitByte > TargetByte)
		{
			if (OutFile) fclose(OutFile);
			clock_date_t c	= ns2clock(LastTS);

			u64 nsec = LastTS % (u64)1e9;

			u64 msec = (nsec / 1e6); 
			nsec = nsec - msec * 1e6;

			u64 usec = (nsec / 1e3); 
			nsec = nsec - usec * 1e3;

			sprintf(FileName, "%s_%02i%02i%02i.%03lli.%03lli.%03lli", OutFileName, c.hour, c.min, c.sec, msec, usec, nsec); 
			OutFile 		= fopen(FileName, "wb");
			if (!OutFile)
			{
				printf("OutputFilename is invalid [%s]\n", FileName);
				break;	
			}	
			fwrite(&HeaderMaster, 1, sizeof(HeaderMaster), OutFile);	

			SplitByte = 0;

			double dT = (clock_ns() - StartTS) / 1e9;
			double Bps = (TotalByte * 8.0) / dT; 
			printf("[%.3f H] %s : Total Bytes %.3f GB Speed: %.3fGbps : New Split\n", dT / (60*60), FileName, TotalByte / 1e9, Bps / 1e9);
		}

		// write output
		int wlen = fwrite(Pkt, 1, sizeof(PCAPPacket_t) + PktHeader->LengthCapture, OutFile);
		if (wlen != sizeof(PCAPPacket_t) + PktHeader->LengthCapture)
		{
			printf("write failure. possibly out of disk space\n");
			break;
		}

		SplitByte += sizeof(PCAPPacket_t) + PktHeader->LengthCapture;
		TotalByte += sizeof(PCAPPacket_t) + PktHeader->LengthCapture;
		TotalPkt  += 1; 

		if ((TotalPkt % (u64)1e6) == 0)
		{
			double dT = (clock_ns() - StartTS) / 1e9;
			double Bps = (TotalByte * 8.0) / dT; 
			printf("[%.3f H] %s : Total Bytes %.3f GB Speed: %.3fGbps\n", dT / (60*60), FileName, TotalByte / 1e9, Bps / 1e9);
		}

	}
	fclose(OutFile);

	printf("Complete\n");

	return 0;
}
