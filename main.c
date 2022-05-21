//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2017-2022, fmad engineering llc 
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
#define FILENAME_TSTR_HHMMSS_TZ			8
#define FILENAME_TSTR_HHMMSS_NS			9
#define FILENAME_TSTR_HHMMSS_SUB		10	
#define FILENAME_STRFTIME				12	

#define OUTPUT_MODE_NULL				0					// null mode for performance testing 
#define OUTPUT_MODE_CAT					1					// cat > blah.pcap
#define OUTPUT_MODE_RCLONE				2					// rclone rcat 
#define OUTPUT_MODE_CURL				3					// curl 
	
//---------------------------------------------------------------------------------------------
// pcap headers

#define PCAPHEADER_MAGIC_NANO		0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC		0xa1b2c3d4
#define PCAPHEADER_MAGIC_FMAD		0x1337bab3

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

// packet header
typedef struct FMADPacket_t
{
	u64             TS;                     // 64bit nanosecond epoch

	u32             LengthCapture   : 16;   // length captured
	u32             LengthWire      : 16;   // Length on the wire

	u32             PortNo          :  8;   // Port number
	u32             Flag            :  8;   // flags
	u32             pad0            : 16;

} __attribute__((packed)) FMADPacket_t;

#define FMAD_PACKET_FLAG_FCS		(1<<0)		// flags invalid FCS was captured 

// header per packet
typedef struct FMADHeader_t
{
	u16				PktCnt;					// number of packets
	u16				CRC16;

	u32				BytesWire;				// total wire bytes  
	u32				BytesCapture;			// total capture bytes 
	u32				Length;					// length of this block in bytes

	u64				TSStart;				// TS of first packet
	u64				TSEnd;					// TS of last packet 

	// internal performance stats passed downstream
	u64				BytePending;			// how many bytes pending 
	u16				CPUActive;				// cpu pct stream_cat is active  
	u16				CPUFetch;	
	u16				CPUSend;	
	u16				pad1;			

} __attribute__((packed)) FMADHeader_t;

//-------------------------------------------------------------------------------------------------
// input mode 

#define INPUT_MODE_NULL		0
#define INPUT_MODE_PCAP		1
#define INPUT_MODE_FMAD		2

static u8*		s_FMADChunkBuffer	= NULL;

double TSC2Nano 					= 0;
static u8 		s_FileNameSuffix[4096];			// suffix to apply to output filename
static u8		s_strftimeFormat[1024];			// strftime format

// args for different outputs

static u8		s_CURLArg[4096] 	= { 0 };	// curl cmd line args for curl	
static u8		s_CURLPath[4096] 	= { 0 };	// curl uri path 
static u8		s_CURLPrefix[4096] 	= { 0 };	// curl filename prefix 

static u8		s_PipeCmd[4096] 	= { 0 };	// allow compression and other stuff

// hooks to run local scripts
static bool		s_ScriptNew				= false;	// run this script before every filefile 
static u8		s_ScriptNewCmd[4096]	= { 0 };

// chomp every packet by x bytes. used for FCS / footer removal
static u32		s_PacketChomp			= 0;		// chomp every packet by this bytes

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

	printf("--cpu  <cpu id>                : bind specifically to a CPU\n");
	printf("\n");
	printf("-v                             : verbose output\n");
	printf("--split-byte  <byte count>     : split by bytes\n");
	printf("--split-time  <nanoseconds>    : split by time\n");
	printf("\n");
	printf("--filename-epoch-sec           : output epoch sec  filename\n");
	printf("--filename-epoch-sec-startend  : output epoch sec start/end filename\n");
	printf("--filename-epoch-msec          : output epoch msec filename\n");
	printf("--filename-epoch-usec          : output epoch usec filename\n");
	printf("--filename-epoch-nsec          : output epoch nsec filename\n");

	printf("--filename-tstr-HHMM           : output time string filename (Hour Min)\n");
	printf("--filename-tstr-HHMMSS         : output time string filename (Hour Min Sec)\n");
	printf("--filename-tstr-HHMMSS_TZ      : output time string filename (Hour Min Sec) plus timezone\n");
	printf("--filename-tstr-HHMMSS_NS      : output time string filename (Hour Min Sec Nanos)\n");
	printf("--filename-tstr-HHMMSS_SUB     : output time string filename (Hour Min Sec Subseconds)\n");
	printf("--filename-strftime \"string\" : output time string to strftime printed string\n");
	printf("\n");
	printf("--filename-suffix              : filename suffix (default .pcap)\n");
	printf("\n");
	printf("--pipe-cmd                     : introduce a pipe command before final output\n");
	printf("--rclone                       : endpoint is an rclone endpoint\n");
	printf("--curl <args> <prefix>         : endpoint is curl via ftp\n");
	printf("--null                         : null performance mode\n");
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

	case FILENAME_TSTR_HHMMSS_TZ:
		{
 			time_t t = time(NULL);
			struct tm lt = {0};
     		localtime_r(&t, &lt);

			s32 Offset = lt.tm_gmtoff;

			u32 TZSign = '+';
			if (Offset < 0)
			{
				TZSign = '-';
				Offset = -Offset;
			}
			s32 TZHour = Offset/(60*60);
			s32 TZMin  = Offset - TZHour * 60 * 60;

			clock_date_t c	= ns2clock(TS);

			u64 nsec = TS % (u64)1e9;

			u64 msec = (nsec / 1e6); 
			nsec = nsec - msec * 1e6;

			u64 usec = (nsec / 1e3); 
			nsec = nsec - usec * 1e3;

			sprintf(FileName, "%s_%04i-%02i-%02i_%02i:%02i:%02i%c%02i:%02i%s", BaseName, c.year, c.month, c.day, c.hour, c.min, c.sec, TZSign, TZHour, TZMin, s_FileNameSuffix); 
		}
		break;

	case FILENAME_STRFTIME:
		{
			u8 TimeStr[1024];

			time_t t0 = TS / 1e9;
			struct tm* t = localtime(&t0);
			strftime(TimeStr, sizeof(TimeStr), s_strftimeFormat, t);

			sprintf(FileName, "%s_%s%s", BaseName, TimeStr, s_FileNameSuffix); 
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

	case FILENAME_TSTR_HHMMSS_SUB:
		{
			clock_date_t c	= ns2clock(TS);

			u64 nsec = TS % (u64)1e9;

			u64 msec = (nsec / 1e6); 
			nsec = nsec - msec * 1e6;

			u64 usec = (nsec / 1e3); 
			nsec = nsec - usec * 1e3;

			sprintf(FileName, "%s_%04i%02i%02i_%02i-%02i-%02i.%03lli%03lli%03lli%s", BaseName, c.year, c.month, c.day, c.hour, c.min, c.sec, msec, usec, nsec, s_FileNameSuffix); 
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
static void GeneratePipeCmd(u8* Cmd, u32 Mode, u8* FileName)
{
	switch (Mode)
	{
	case OUTPUT_MODE_NULL:
		sprintf(Cmd, "%s > /dev/null", s_PipeCmd);
		break;

	case OUTPUT_MODE_CAT:
		sprintf(Cmd, "%s > '%s'", s_PipeCmd, FileName);
		break;

	case OUTPUT_MODE_RCLONE:
		sprintf(Cmd, "%s | rclone --config=/opt/fmadio/etc/rclone.conf --ignore-checksum rcat %s", s_PipeCmd, FileName);
		break;

	case OUTPUT_MODE_CURL:
		sprintf(Cmd, "%s | curl -s -T - %s \"%s%s%s\"", s_PipeCmd, s_CURLArg, s_CURLPath, s_CURLPrefix, FileName);
		break;
	}
}

//-------------------------------------------------------------------------------------------------
// rename file 
static void RenameFile(u32 Mode, u8* FileNamePending, u8* FileName, u8* CurlCmd)
{
	switch (Mode)
	{
	case OUTPUT_MODE_NULL:
		break;

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

	case OUTPUT_MODE_CURL:
		{
			u8 Cmd[4096];
			sprintf(Cmd, "curl -s -p %s \"%s\" -Q \"-RNFR %s%s\" -Q \"-RNTO %s%s\" > /dev/null", s_CURLArg, s_CURLPath, s_CURLPrefix, FileNamePending, s_CURLPrefix, FileName);
			printf("Cmd [%s]\n", Cmd);
			system(Cmd);
		}
		break;
	}
}

//-------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	char* OutFileName 	= "";

	u64 TargetByte 		= 0;
	s64 TargetTime 		= 0;

	u32 SplitMode		= 0;
	u32 FileNameMode	= FILENAME_TSTR_HHMMSS;

	u32 CPUID			= 0;

	// default do nothing output
	strcpy(s_PipeCmd, "cat");

	// args sent to curl, e.g target IP password etc 
	u8 CurlCmd[4096];		
	strcpy(CurlCmd, "");


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
			fprintf(stderr, "    UID [%s]\n", UID);
		}
		else if (strcmp(argv[i], "-o") == 0)
		{
			OutFileName = argv[i+1];
			fprintf(stderr, "    OutputName [%s]\n", OutFileName);
			i++;
		}
		else if (strcmp(argv[i], "--cpu") == 0)
		{
			CPUID = atoi(argv[i+1]);
			i++;
			fprintf(stderr, "    CPU ID:%i\n", CPUID);
		}
		else if (strcmp(argv[i], "--split-byte") == 0)
		{
			SplitMode = SPLIT_MODE_BYTE; 

			TargetByte = atof(argv[i+1]);
			i++;

			fprintf(stderr, "    Split Every %lli Bytes %.3f GByte\n", TargetByte, TargetByte / (double)kGB(1));
		}
		else if (strcmp(argv[i], "--split-time") == 0)
		{
			SplitMode = SPLIT_MODE_TIME; 

			TargetTime = atof(argv[i+1]);
			i++;

			fprintf(stderr, "    Split Every %lli Sec\n", TargetTime / 1e9);
		}
		else if (strcmp(argv[i], "--packet-chomp") == 0)
		{
			s_PacketChomp = atof(argv[i+1]);
			i++;
			fprintf(stderr, "    chomp every packet by %i bytes\n", s_PacketChomp);
		}
		else if (strcmp(argv[i], "--filename-epoch-sec") == 0)
		{
			fprintf(stderr, "    Filename EPOCH Sec\n");
			FileNameMode	= FILENAME_EPOCH_SEC;
		}
		else if (strcmp(argv[i], "--filename-epoch-sec-startend") == 0)
		{
			fprintf(stderr, "    Filename EPOCH Sec Start/End\n");
			FileNameMode	= FILENAME_EPOCH_SEC_STARTEND;
		}
		else if (strcmp(argv[i], "--filename-epoch-msec") == 0)
		{
			fprintf(stderr, "    Filename EPOCH MSec\n");
			FileNameMode	= FILENAME_EPOCH_MSEC;
		}
		else if (strcmp(argv[i], "--filename-epoch-usec") == 0)
		{
			fprintf(stderr, "    Filename EPOCH Micro Sec\n");
			FileNameMode	= FILENAME_EPOCH_USEC;
		}
		else if (strcmp(argv[i], "--filename-epoch-nsec") == 0)
		{
			fprintf(stderr, "    Filename EPOCH nano Sec\n");
			FileNameMode	= FILENAME_EPOCH_NSEC;
		}
		else if (strcmp(argv[i], "--filename-tstr-HHMM") == 0)
		{
			fprintf(stderr, "    Filename TimeString HHMM\n");
			FileNameMode	= FILENAME_TSTR_HHMM;
		}
		else if (strcmp(argv[i], "--filename-tstr-HHMMSS") == 0)
		{
			fprintf(stderr, "    Filename TimeString HHMMSS\n");
			FileNameMode	= FILENAME_TSTR_HHMMSS;
		}
		else if (strcmp(argv[i], "--filename-tstr-HHMMSS_TZ") == 0)
		{
			fprintf(stderr, "    Filename TimeString HHMMSS_TZ\n");
			FileNameMode	= FILENAME_TSTR_HHMMSS_TZ;
		}

		else if (strcmp(argv[i], "--filename-tstr-HHMMSS_NS") == 0)
		{
			fprintf(stderr, "    Filename TimeString HHMMSS Nano\n");
			FileNameMode	= FILENAME_TSTR_HHMMSS_NS;
		}
		else if (strcmp(argv[i], "--filename-tstr-HHMMSS_SUB") == 0)
		{
			fprintf(stderr, "    Filename TimeString HHMMSS Subseconds\n");
			FileNameMode	= FILENAME_TSTR_HHMMSS_SUB;
		}
		else if (strcmp(argv[i], "--filename-strftime") == 0)
		{
			FileNameMode	= FILENAME_STRFTIME;
			strncpy(s_strftimeFormat, argv[i+1], sizeof(s_strftimeFormat));

			fprintf(stderr, "    Filename TimeString (%s)\n", s_strftimeFormat);
			i++;
		}
		else if (strcmp(argv[i], "--pipe-cmd") == 0)
		{
			strncpy(s_PipeCmd, argv[i+1], sizeof(s_PipeCmd));	
			fprintf(stderr, "    pipe cmd [%s]\n", s_PipeCmd);
			i++;
		}
		else if (strcmp(argv[i], "--filename-suffix") == 0)
		{
			strncpy(s_FileNameSuffix, argv[i+1], sizeof(s_FileNameSuffix));	
			fprintf(stderr, "    Filename Suffix [%s]\n", s_FileNameSuffix);
			i++;
		}
		else if (strcmp(argv[i], "--rclone") == 0)
		{
			OutputMode = OUTPUT_MODE_RCLONE;
			fprintf(stderr, "    Output Mode RClone\n");
		}
		else if (strcmp(argv[i], "--curl") == 0)
		{
			strncpy(s_CURLArg , 	argv[i+1], sizeof(s_CURLArg)	);	
			strncpy(s_CURLPath, 	argv[i+2], sizeof(s_CURLPath)	);	

			// seperate the path from the filename prefix 
			for (int i=strlen(s_CURLPath)-1; i >= 0; i--)
			{
				if (s_CURLPath[i] == '/')
				{
					printf("copy %i %i %s\n", i, strlen(s_CURLPath), s_CURLPath ); 

					int Pos = 0;
					for (int j=i+1; j < strlen(s_CURLPath); j++)
					{
						s_CURLPrefix[Pos++] = s_CURLPath[j];	
					}
					s_CURLPrefix[Pos++] = 0;

					// drop the filename prefix
					s_CURLPath[i+1] = 0;
					break;
				}
			}

			OutputMode = OUTPUT_MODE_CURL;
			fprintf(stderr, "    Output Mode CRUL (%s) (%s) (%s)\n", s_CURLArg, s_CURLPath, s_CURLPrefix);
			i += 2;
		}
		else if (strcmp(argv[i], "--null") == 0)
		{
			OutputMode = OUTPUT_MODE_NULL;
			fprintf(stderr, "    Output Mode NULL\n");
		}
		else if (strcmp(argv[i], "--script-new") == 0)
		{
			s_ScriptNew = true;
			strncpy(s_ScriptNewCmd, argv[i+1], sizeof(s_ScriptNewCmd));	

			fprintf(stderr, "    Script New Hook [%s]\n", s_ScriptNewCmd);
			i++;
		}
		else
		{
			fprintf(stderr, "unknown command [%s]\n", argv[i]);
			return 0;
		}
	}

	// set cpu affinity
	if (CPUID != -1)
	{
		cpu_set_t	MainCPUS;
		CPU_ZERO(&MainCPUS);
		CPU_SET(CPUID, &MainCPUS);
		pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &MainCPUS);
	}

	// check for valid config
	switch (SplitMode)
	{
	case SPLIT_MODE_BYTE:
	case SPLIT_MODE_TIME:
		break;

	default:
		fprintf(stderr, "invalid config. no split type time/bytes specified\n");
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
	case FILENAME_TSTR_HHMMSS_TZ:
	case FILENAME_TSTR_HHMMSS_NS:
	case FILENAME_TSTR_HHMMSS_SUB:
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

	// work out the input file format
	bool InputMode 		= INPUT_MODE_NULL;

	u64 TScale 			= 0;
	switch (HeaderMaster.Magic)
	{
	case PCAPHEADER_MAGIC_NANO: 
		printf("PCAP Nano\n"); 
		TScale 			= 1;    
		InputMode		= INPUT_MODE_PCAP;
		break;

	case PCAPHEADER_MAGIC_USEC: 
		printf("PCAP Micro\n"); 
		TScale 			= 1000; 
		InputMode		= INPUT_MODE_PCAP;
		break;

	case PCAPHEADER_MAGIC_FMAD: 
		fprintf(stderr, "FMAD Format Chunked\n");
		TScale 			= 1; 
		InputMode		= INPUT_MODE_FMAD;

		break;
	}

	// force it to nsec pacp
	HeaderMaster.Magic 		= PCAPHEADER_MAGIC_NANO;
	HeaderMaster.Major 		= PCAPHEADER_MAJOR;
	HeaderMaster.Minor 		= PCAPHEADER_MINOR;
	HeaderMaster.TimeZone 	= 0;
	HeaderMaster.SigFlag 	= 0;
	HeaderMaster.SnapLen 	= 0xffff;
	HeaderMaster.Link 		= 1;				// set as ethernet

	// split stats
	u64 StartTS					= clock_ns();
	u64 LastTSC					= rdtsc(); 
	u64 TotalByte				= 0;
	u64 TotalPkt				= 0;
	u32 TotalSplit				= 0;

	u64 SplitByte	 			= -1;	
	FILE* OutFile 				= NULL;

	u64 LastTS					= 0;
	u64 SplitTS					= 0;
	u64 LastSplitTS				= 0;

	u8* 			Pkt			= malloc(1024*1024);	
	PCAPPacket_t*	PktHeader	= (PCAPPacket_t*)Pkt;

	u8 FileName[1024];			// filename of the final output
	u8 FileNamePending[1024];	// filename of the currently active write

	// chunked fmad buffer
	u32 FMADChunkBufferPos	= 0;
	u32 FMADChunkBufferMax	= 0;
	u8* FMADChunkBuffer 	= NULL; 

	u32 FMADChunkPktCnt		= 0;
	u32 FMADChunkPktMax		= 0;

	// init
	switch (InputMode)
	{
	case INPUT_MODE_PCAP:
		break;

	case INPUT_MODE_FMAD:
		FMADChunkBufferPos	= 0;
		FMADChunkBufferMax	= 0;
		FMADChunkBuffer		= malloc(1024*1024);
		break;
	}

	// stats
	u64 LastPrintTS 		= 0;
	u64 LastPrintByte 		= 0;
	u64 LastPrintPkt 		= 0;

	bool IsExit = false;
	while (!IsExit)
	{
		switch (InputMode)
		{
		// standard pcap mode
		case INPUT_MODE_PCAP:
		{
			// header 
			int rlen = fread(PktHeader, 1, sizeof(PCAPPacket_t), FIn);
			if (rlen != sizeof(PCAPPacket_t))
			{
				printf("Invalid packet read size: %i (%i)\n", rlen, errno);
				IsExit = true;
				break;
			}

			// validate size
			if ((PktHeader->LengthCapture == 0) || (PktHeader->LengthCapture > 128*1024)) 
			{
				printf("Invalid packet length: %i : %s\n", PktHeader->LengthCapture, FormatTS(LastTS) );
				IsExit = true;
				break;
			}

			// payload
			rlen = fread(PktHeader + 1, 1, PktHeader->LengthCapture, FIn);
			if (rlen != PktHeader->LengthCapture)
			{
				printf("payload read fail %i (%i) expect %i\n", rlen, errno, PktHeader->LengthCapture);
				IsExit = true;
				break;
			}
		}
		break;

		case INPUT_MODE_FMAD:
		{
			// load new buffer
			if (FMADChunkPktCnt >= FMADChunkPktMax)
			{
				FMADHeader_t Header;

				u32 Timeout = 0; 
				while (true)
				{
					int rlen = fread(&Header, 1, sizeof(Header), FIn);
					if (rlen != sizeof(Header))
					{
						fprintf(stderr, "FMADHeader read fail: %i %i : %i\n", rlen, sizeof(Header), errno, strerror(errno));
						IsExit = true;
						break;
					}

					if (Header.PktCnt > 0) break;
					assert(Timeout++ < 1e6);
				}

				// sanity checks
				assert(Header.Length < 1024*1024);
				assert(Header.PktCnt < 1e6);

				rlen = fread(FMADChunkBuffer, 1, Header.Length, FIn);
				if (rlen != Header.Length)
				{
					fprintf(stderr, "FMADHeader payload read fail: %i %i : %i\n", rlen, Header.Length, errno, strerror(errno));
					break;
				}

				FMADChunkBufferPos 	= 0;
				FMADChunkBufferMax 	= Header.Length;

				FMADChunkPktCnt 	= 0;
				FMADChunkPktMax 	= Header.PktCnt;
			}

			// FMAD to PCAP packet
			FMADPacket_t* FMADPacket = (FMADPacket_t*)(FMADChunkBuffer + FMADChunkBufferPos);

			PktHeader->Length			= FMADPacket->LengthWire;	
			PktHeader->LengthCapture	= FMADPacket->LengthCapture;	
			PktHeader->Sec				= FMADPacket->TS / (u64)1e9;	
			PktHeader->NSec				= FMADPacket->TS % (u64)1e9;	

			// payload
			memcpy(PktHeader + 1, FMADPacket + 1, FMADPacket->LengthCapture);

			FMADChunkPktCnt++;
			FMADChunkBufferPos += sizeof(FMADPacket_t) + FMADPacket->LengthCapture;
		}
		break;

		default:
			assert(false);
			break;
		}
		// 64b epoch 
		u64 TS = (u64)PktHeader->Sec * ((u64)1e9) + (u64)PktHeader->NSec * TScale;

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
					RenameFile(OutputMode, FileNamePending, FileName, CurlCmd);
				}

				// run local new script 
				if (s_ScriptNew)
				{
					printf("Script [%s]\n", s_ScriptNewCmd);
					system(s_ScriptNewCmd);
				}

				GenerateFileName(FileNameMode, FileName, OutFileName, TS, LastSplitTS);
				sprintf(FileNamePending, "%s.pending", FileName);

				u8 Cmd[4095];
				GeneratePipeCmd(Cmd, OutputMode, FileNamePending);

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

					// round up the first 1/4 of the time target
					// as the capture processes does not split preceisely at 0.00000000000
					// thus allow for some variance
					SplitTS = ((TS + (TargetTime/4)) / TargetTime);
					SplitTS *= TargetTime;
					//fprintf(stderr, "split time: %lli TS:%lli dTS:%lli\n", SplitTS, TS, dTS);

					// create null PCAPs for anything missing 

					// close file and rename
					if (OutFile)
					{
						fclose(OutFile);

						// rename to file name 
						RenameFile(OutputMode, FileNamePending, FileName, CurlCmd);
					}

					// run local new script 
					if (s_ScriptNew)
					{
						printf("Script [%s]\n", s_ScriptNewCmd);
						system(s_ScriptNewCmd);
					}


					GenerateFileName(FileNameMode, FileName, OutFileName, SplitTS + TargetTime, SplitTS);
					sprintf(FileNamePending, "%s.pending", FileName);

					//OutFile 		= fopen(FileNamePending, "wb");

					u8 Cmd[4095];
					GeneratePipeCmd(Cmd, OutputMode, FileNamePending);
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

		// optionally chomp packets before outputing
		PktHeader->Length			-= s_PacketChomp; 
		PktHeader->LengthCapture	-= s_PacketChomp; 

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
			TotalSplit++;

			u8 TimeStr[1024];
			clock_date_t c	= ns2clock(TS);
			sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);

			double dT = (clock_ns() - StartTS) / 1e9;
			double Bps = (TotalByte * 8.0) / dT; 
			printf("[%.3f H][%s] %s : Total Bytes %.3f GB Speed: %.3f Gbps : New Split\n", dT / (60*60), TimeStr, FileName, TotalByte / 1e9, Bps / 1e9);
			fflush(stdout);
			fflush(stderr);
		}

		// assumein 2.5Ghz clock or so, just need some periodic printing 
		if ((rdtsc() - LastTSC) > 2.5*1e9) 
		{
			LastTSC = rdtsc();

			u8 TimeStr[1024];
			clock_date_t c	= ns2clock(LastTS);
			sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);

			u64 TS = clock_ns();

			double dT 		= (TS - LastPrintTS) / 1e9; 
			double dByte 	= TotalByte - LastPrintByte; 
			double dPacket 	= TotalPkt  - LastPrintPkt; 
			double Bps 		= (dByte * 8.0) / dT; 
			double Pps 		= dPacket / dT; 
			printf("[%.3f H][%s] %s : Total Bytes %.3f GB Speed: %.3f Gbps %.3f Mpps : TotalSplit %i\n", dT / (60*60), TimeStr, FileName, TotalByte / 1e9, Bps / 1e9, Pps / 1e6, TotalSplit);
			fflush(stdout);
			fflush(stderr);

			LastPrintTS 	= TS;
			LastPrintByte 	= TotalByte;
			LastPrintPkt 	= TotalPkt;
		}
	}

	// final close and re-name
	fclose(OutFile);
	RenameFile(OutputMode, FileNamePending, FileName, CurlCmd);

	printf("Complete\n");

	return 0;
}
