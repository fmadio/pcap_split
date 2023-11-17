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
#include <sys/types.h>
#include <linux/sched.h>
#include <pwd.h>
#include <grp.h>

#include "fTypes.h"

// fmadio platform lxc_ring support
// https://github.com/fmadio/platform 
#ifdef FMADIO_LXCRING

	#include "platform/include/fmadio_packet.h"

#endif

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
#define OUTPUT_MODE_SSH					4					// pipe to ssh 

volatile bool g_SignalExit			= 0;					// signal handlered requesting exit		
	
//---------------------------------------------------------------------------------------------
// pcap headers

// defined in fmadio_packet.h  
#ifndef  __FMADIO_PACKET_H__

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
	u32				LengthWire;			// length on the wire

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

#endif


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
#define INPUT_MODE_LXCRING	3

static u8*		s_FMADChunkBuffer	= NULL;

double TSC2Nano 					= 0;
static u8 		s_FileNameSuffix[4096];			// suffix to apply to output filename
static u8		s_strftimeFormat[1024];			// strftime format
static uid_t	s_FileNameUID;					// change owner of the file
static gid_t	s_FileNameGID;					// change owner of the file

// args for different outputs
static u8		s_CURLArg[4096] 	= { 0 };	// curl cmd line args for curl	
static u8		s_CURLPath[4096] 	= { 0 };	// curl uri path 
static u8		s_CURLPrefix[4096] 	= { 0 };	// curl filename prefix 

static u8		s_SSHArg[4096] 		= { 0 };	// ssh cmd line args for curl	
static u8		s_SSHOpt[4096] 		= { 0 };	// ssh command options 
static u8		s_SSHHost[4096] 	= { 0 };	// ssh hostname 
static u8		s_SSHPath[4096] 	= { 0 };	// ssh target path 
static u8		s_SSHPrefix[4096] 	= { 0 };	// ssh filename prefix 


static u8		s_PipeCmd[4096] 	= { 0 };	// allow compression and other stuff

// hooks to run local scripts
static bool		s_ScriptNew				= false;	// run this script before every filefile 
static u8		s_ScriptNewCmd[4096]	= { 0 };

static bool		s_ScriptClose			= false;	// run this script when finishing a split 
static u8		s_ScriptCloseCmd[4096]	= { 0 };

// chomp every packet by x bytes. used for FCS / footer removal
static u32		s_PacketChomp			= 0;		// chomp every packet by this bytes

// lxc ring 
static u8*							s_LXCRingPath	= NULL;	// path to the lxc ring
static s32							s_LXCRingFD		= 0;	// file handle
static struct fFMADRingHeader_t* 	s_LXCRing;				// actual lxc ring struct

// roll period
static bool		s_RollPeriodSetup			= true;		// has the roll period been setup? only enabled if --roll-period is set
static s64		s_RollPeriod				= 0;		// advise what the roll period is
static s64		s_RollLocalTS				= 0;		// calculate what the start of the roll is in epoch 

static s64		s_TZOffset					= 0;		// offset to local time

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
	printf("--ring  <lxc_ring path>        : read data from fmadio lxc ring\n");
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
	printf("--curl <args> <prefix>         : endpoint is curl\n");
	printf("--ssh  <args> <prefix>         : endpoint is ssh\n");
	printf("--null                         : null performance mode\n");
	printf("-Z <username>                  : change ownership to username\n");
	printf("-Z <username.group>            : change ownership to username.group\n");
	printf("-Z <UID:GID>                   : change ownership using UID GID\n");
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

//-------------------------------------------------------------------------------

static void lsignal (int i, siginfo_t* si, void* context)
{
	fprintf(stderr, "signal received SIG:%i : %p\n", i, context);

	fprintf(stderr, "   si_signo  : %4i %08x\n", si->si_signo, si->si_signo);
	fprintf(stderr, "   si_errno  : %4i %08x\n", si->si_errno, si->si_errno);
	fprintf(stderr, "   si_code   : %4i %08x\n", si->si_code,  si->si_code);
	//fprintf(stderr, "   si_trapno : %i\n", si->si_trapno);

	switch (i)
	{
	case SIGTRAP:
	case SIGSEGV:
	case SIGBUS:
		fprintf(stderr, "    Bus error: 0x%016llx\n", si->si_addr);
		break;

	case SIGTERM:
	case SIGINT:
		fprintf(stderr, "    kill\n");
		break;

	default:
		fprintf(stderr, "    undef signal\n"); 
		break;
	}
	fflush(stderr);

	signal(i, SIG_DFL); /* if another SIGINT happens before lstop, terminate process (default action) */

	// get execution context
	//mcontext_t* mcontext = &((ucontext_t*)context)->uc_mcontext;
	//fprintf(stderr, "   EPI: %016llx\n", mcontext->gregs[REG_RIP]);

	// signal related threads to exit
	g_SignalExit = 1;
}


//-------------------------------------------------------------------------------------------------
// various different naming formats 
static void GenerateFileName(u32 Mode, u8* FileName, u8* BaseName, u64 TS, u64 TSLast)
{
	switch (Mode)
	{
	case FILENAME_EPOCH_SEC:
		{
			sprintf(FileName, "%s%lli%s", BaseName, (u64)(TS / 1e9), s_FileNameSuffix); 
		}
		break;
	case FILENAME_EPOCH_SEC_STARTEND:
		{
			sprintf(FileName, "%s%lli-%lli%s", BaseName, (u64)(TS / 1e9), (u64)(TSLast / 1e9), s_FileNameSuffix); 
		}
		break;
	case FILENAME_EPOCH_MSEC:
		{
			sprintf(FileName, "%s%lli%s", BaseName, (u64)(TS/1e6), s_FileNameSuffix);
		}
		break;

	case FILENAME_EPOCH_USEC:
		{
			sprintf(FileName, "%s%lli%s", BaseName, (u64)(TS/1e3), s_FileNameSuffix);
		}
		break;

	case FILENAME_EPOCH_NSEC:
		{
		sprintf(FileName, "%s%lli%s", BaseName, TS, s_FileNameSuffix);
		}
		break;

	case FILENAME_TSTR_HHMM:
		{
			clock_date_t c	= ns2clock(TS);

			u64 nsec = TS % (u64)1e9;

			u64 msec = (nsec / 1e6); 
			nsec = nsec - msec * 1e6;

			u64 usec = (nsec / 1e3); 
			nsec = nsec - usec * 1e3;

			sprintf(FileName, "%s%04i%02i%02i_%02i%02i%s", BaseName, c.year, c.month, c.day, c.hour, c.min, s_FileNameSuffix);
		}
		break;

	case FILENAME_TSTR_HHMMSS:
		{
			clock_date_t c	= ns2clock(TS);

			sprintf(FileName, "%s%04i%02i%02i_%02i%02i%02i%s", BaseName, c.year, c.month, c.day, c.hour, c.min, c.sec, s_FileNameSuffix); 
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

			sprintf(FileName, "%s%04i-%02i-%02i_%02i:%02i:%02i%c%02i:%02i%s", BaseName, c.year, c.month, c.day, c.hour, c.min, c.sec, TZSign, TZHour, TZMin, s_FileNameSuffix); 
		}
		break;

	case FILENAME_STRFTIME:
		{
			u8 TimeStr[1024];

			time_t t0 = TS / 1e9;
			struct tm* t = localtime(&t0);
			strftime(TimeStr, sizeof(TimeStr), s_strftimeFormat, t);

			sprintf(FileName, "%s%s%s", BaseName, TimeStr, s_FileNameSuffix); 
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

			sprintf(FileName, "%s%04i%02i%02i_%02i%02i%02i.%03lli.%03lli.%03lli%s", BaseName, c.year, c.month, c.day, c.hour, c.min, c.sec, msec, usec, nsec, s_FileNameSuffix); 
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

			sprintf(FileName, "%s%04i%02i%02i_%02i-%02i-%02i.%03lli%03lli%03lli%s", BaseName, c.year, c.month, c.day, c.hour, c.min, c.sec, msec, usec, nsec, s_FileNameSuffix); 
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

	case OUTPUT_MODE_SSH:
		sprintf(Cmd, "%s | ssh %s %s \" cat > %s%s%s\"", s_PipeCmd, s_SSHOpt, s_SSHHost, s_SSHPath, s_SSHPrefix, FileName);
		break;

	}
}

//-------------------------------------------------------------------------------------------------
// generate a filename for description purposes 
static void GenerateDescription(u8* Cmd, u32 Mode, u8* FileName)
{
	switch (Mode)
	{
	case OUTPUT_MODE_NULL:
		sprintf(Cmd, "NULL:");
		break;

	case OUTPUT_MODE_CAT:
		sprintf(Cmd, "FILE:%s", FileName);
		break;

	case OUTPUT_MODE_RCLONE:
		sprintf(Cmd, "RCLONE:%s", s_PipeCmd, FileName);
		break;

	case OUTPUT_MODE_CURL:
		sprintf(Cmd, "CURL:%s%s%s", s_CURLPath, s_CURLPrefix, FileName);
		break;

	case OUTPUT_MODE_SSH:
		sprintf(Cmd, "SSH:%s:%s%s%s", s_SSHHost, s_SSHPath, s_SSHPrefix, FileName);
		break;
	}
}


//-------------------------------------------------------------------------------------------------
// rename file 
static void RenameFile(u32 Mode, u8* FileNamePending, u8* FileName)
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

	case OUTPUT_MODE_SSH:
		{
			u8 Cmd[4*1024];
			sprintf(Cmd, "echo \"mv %s%s%s %s%s%s\" | /usr/local/bin/ssh -T %s %s", s_SSHPath, s_SSHPrefix, FileNamePending, s_SSHPath, s_SSHPrefix, FileName, s_SSHOpt, s_SSHHost);
			printf("Cmd [%s] %i\n", Cmd, strlen(Cmd) );
			system(Cmd);
		}
		break;
	}
}

//-------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	char* OutFileName 	= "";

	u64 TargetByte 			= 0;
	s64 TargetTime 			= 0;
	s64 TargetTimeRoundup	= 0;

	u32 SplitMode			= 0;
	u32 FileNameMode		= FILENAME_TSTR_HHMMSS;

	u32 CPUList[128];
	u32 CPUListCnt		= 0;

	// default do nothing output
	strcpy(s_PipeCmd, "cat");


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

		// parse a list of avaliable CPUs
		else if (strcmp(argv[i], "--cpu") == 0)
		{
			u8* CPUStr   = argv[i+1];
			u32 CPUStrLen = strlen(CPUStr);
			u8* CPUStart = CPUStr; 
			for (int i=0; i <= CPUStrLen; i++)
			{
				if ((CPUStr[i] == ',') || (CPUStr[i] == 0))
				{
					CPUStr[i] = 0;

					u32 CPU = atoi(CPUStart);
					CPUList[CPUListCnt++] = CPU;

					fprintf(stderr, "CPU [%i]\n", CPU);
					CPUStart = &CPUStr[i+1];
				}
			}

			i++;
			fprintf(stderr, "    CPUList Cnt:%i [", CPUListCnt);
			for (int i=0; i < CPUListCnt; i++)
			{
				fprintf(stderr, "%i ", CPUList[i]);
			}
			fprintf(stderr, "]\n", CPUList[i]);
		}
		else if (strcmp(argv[i], "--ring") == 0)
		{
			#ifndef FMADIO_LXCRING
				fprintf(stderr, "ERROR: LXC Ring support not comipled in\n");
				assert (false);
			#endif

			s_LXCRingPath = argv[i+1];
			fprintf(stderr, "    Input from lxc_ring:%s\n", s_LXCRingPath);
			i++;
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

			fprintf(stderr, "    Split Every %f Sec\n", TargetTime / 1e9);
		}
		else if (strcmp(argv[i], "--split-time-roundup") == 0)
		{
			TargetTimeRoundup  = atof(argv[i+1]);
			i++;

			fprintf(stderr, "    Split Foundup %.6fsec\n", TargetTimeRoundup / 1e9);
		}
		else if (strcmp(argv[i], "--packet-chomp") == 0)
		{
			s_PacketChomp = atof(argv[i+1]);
			i++;
			fprintf(stderr, "    chomp every packet by %i bytes\n", s_PacketChomp);
		}
		else if (strcmp(argv[i], "--roll-period") == 0)
		{
			s_RollPeriodSetup = false;
			s_RollPeriod = atof(argv[i+1]);
			i++;
			fprintf(stderr, "    Roll Period %.3f hours\n", s_RollPeriod/(60*60*1e9) );
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
			fprintf(stderr, "    Output Mode CURL (%s) (%s) (%s)\n", s_CURLArg, s_CURLPath, s_CURLPrefix);
			i += 2;
		}
		else if (strcmp(argv[i], "--ssh") == 0)
		{
			strncpy(s_SSHArg , 	argv[i+1], sizeof(s_SSHArg)	);	

			// seperate the path from the filename prefix 
			u32 PrefixStart = 0;
			for (int i=strlen(s_SSHArg)-1; i >= 0; i--)
			{
				if (s_SSHArg[i] == '/')
				{
					PrefixStart = i;
					//printf("copy %i %i %s\n", i, strlen(s_SSHArg), s_SSHArg ); 

					int Pos = 0;
					for (int j=i+1; j < strlen(s_SSHArg); j++)
					{
						s_SSHPrefix[Pos++] = s_SSHArg[j];	
					}
					s_SSHPrefix[Pos++] = 0;
					assert(Pos < sizeof(s_SSHPrefix));

					// drop the filename prefix
					s_SSHPath[i+1] = 0;
					break;
				}
			}

			// seperate hostname from path 
			u32 PathStart = 0;
			for (int i=strlen(s_SSHArg)-1; i >= 0; i--)
			{
				if (s_SSHArg[i] == ':')
				{
					PathStart = i;
					//printf("copy %i %i %s\n", i, strlen(s_SSHArg), s_SSHArg ); 

					int Pos = 0;
					for (int j=i+1; j <= PrefixStart; j++)
					{
						s_SSHPath[Pos++] = s_SSHArg[j];	
					}
					s_SSHPath[Pos++] = 0;
					assert(Pos < sizeof(s_SSHPath));

					// drop the filename prefix
					s_SSHPath[i+1] = 0;
					break;
				}
			}

			// find host
			u32 HostStart = 0;
			for (int i=PathStart; i >= 0; i--)
			{
				if ((s_SSHArg[i] == ' ') || (i ==0) )
				{
					HostStart = i;
					u32 Pos = 0;
					for (int j=i; j < PathStart; j++)
					{
						s_SSHHost[Pos++] = s_SSHArg[j];
					}
					s_SSHHost[Pos++] = 0; 
					assert(Pos < sizeof(s_SSHHost));

					break;
				}
			}

			u32 Pos = 0;
			for (int i=0; i < HostStart; i++)
			{
				s_SSHOpt[Pos++] = s_SSHArg[i];
			}
			s_SSHOpt[Pos++] = 0; 
			assert(Pos < sizeof(s_SSHOpt));

			OutputMode = OUTPUT_MODE_SSH;
			fprintf(stderr, "    Output Mode SSH Opt    (%s)\n", s_SSHOpt);
			fprintf(stderr, "                    Host   (%s)\n", s_SSHHost);
			fprintf(stderr, "                    Path   (%s)\n", s_SSHPath);
			fprintf(stderr, "                    Prefix (%s)\n", s_SSHPrefix);
			i += 1;
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
		else if (strcmp(argv[i], "--script-close") == 0)
		{
			s_ScriptClose = true;
			strncpy(s_ScriptCloseCmd, argv[i+1], sizeof(s_ScriptCloseCmd));	

			fprintf(stderr, "    Script Close Hook [%s]\n", s_ScriptCloseCmd);
			i++;
		}

		else if (strcmp(argv[i], "-Z") == 0)
		{
			u8* UserName       = argv[i+1]; 

			struct passwd *pwd 	= getpwnam(UserName);
			if (pwd != NULL)
			{
		    	s_FileNameUID		= pwd->pw_uid;
				s_FileNameGID		= pwd->pw_gid;
			}
			else
			{
				// search for UID:GID style
				u8 sUID[128];
				u8 sGID[128];

				u32 UIDPos = 0;
				u32 GIDPos = 0;

				int i=0;
				for (; i < strlen(UserName); i++)
				{
					u32 c = UserName[i];
					if ((c == ':') || (c == '.'))
					{
						sUID[UIDPos] = 0;
						break;
					}

					sUID[UIDPos++] = c;
				}

				// skip :
				i++;

				for (; i < strlen(UserName); i++)
				{
					u32 c = UserName[i];
					sGID[GIDPos++] = c;
				}
				sGID[GIDPos] = 0;

				fprintf(stderr, "UID[%s] GID[%s]\n", sUID, sGID);

		    	s_FileNameUID		= atoi(sUID); 
				s_FileNameGID		= atoi(sGID); 

				// if its not a UID/GID number try it as a username/group string
				if (s_FileNameUID == 0)
				{
					struct passwd *pwd 	= getpwnam(sUID);
					if (pwd != NULL)
					{
		    			s_FileNameUID		= pwd->pw_uid;
					}
				}
				if (s_FileNameGID == 0)
				{
					struct group *grp = getgrnam(sGID);
					if (grp != NULL)
					{
		    			s_FileNameGID		= grp->gr_gid;
					}
				}
			}

			fprintf(stderr, "UserName (%s) %i:%i\n", UserName, s_FileNameUID, s_FileNameGID); 
			i++;
		}
		else
		{
			fprintf(stderr, "unknown command [%s]\n", argv[i]);
			return 0;
		}
	}

	// set cpu affinity
	if (CPUListCnt > 0)
	{
		cpu_set_t	MainCPUS;
		CPU_ZERO(&MainCPUS);

		for (int i=0; i < CPUListCnt; i++)
		{
			CPU_SET(CPUList[i], &MainCPUS);
		}
		pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &MainCPUS);
	}


	// setup signal hanlders
	struct sigaction handler;
	memset(&handler, 0, sizeof(handler));
  	handler.sa_sigaction = lsignal;
    sigemptyset (&handler.sa_mask);
	handler.sa_flags = SA_SIGINFO;

	sigaction (SIGINT, 	&handler, NULL);
	sigaction (SIGTERM, &handler, NULL);
	sigaction (SIGKILL, &handler, NULL);
	sigaction (SIGHUP, 	&handler, NULL);
	sigaction (SIGBUS, 	&handler, NULL);
	sigaction (SIGSEGV, &handler, NULL);

	
	// get the local timezone offset
	// as pcap timestamps are always epoch
  	time_t t = time(NULL);
 	struct tm lt = {0};

	localtime_r(&t, &lt);

	s_TZOffset = (s64)lt.tm_gmtoff * 1e9;
	printf("Offset to GMT is %lli (%s)\n", s_TZOffset, lt.tm_zone);

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
	case FILENAME_STRFTIME:
		break;

	default:
		fprintf(stderr, "invalid filename mode\n");
		break;
	}

	FILE* FIn = stdin; 
	assert(FIn != NULL);

	// work out the input file format
	bool InputMode 		= INPUT_MODE_NULL;
	u64 TScale 			= 0;

	// master pcap header for output
	PCAPHeader_t HeaderMaster;

	// lxc ring as input
	#ifdef FMADIO_LXCRING
	if (s_LXCRingPath)
	{
		InputMode 		= INPUT_MODE_LXCRING;
		TScale 			= 1;

		// open ring
		int ret = FMADPacket_OpenRx(&s_LXCRingFD,
									&s_LXCRing,
									0,
									s_LXCRingPath
								   );
		if (ret < 0)
		{
			fprintf(stderr, "failed to open lxc ring [%s]\n", s_LXCRingPath);
			return 0;
		}
	}
	else
	#endif
	{
		// read header
		int rlen = fread(&HeaderMaster, 1, sizeof(HeaderMaster), FIn);
		if (rlen != sizeof(HeaderMaster))
		{
			printf("Failed to read pcap header\n");
			return 0;
		}

		// what kind of pcap
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
	u64 SplitPkt	 			= -1;	
	u64 SplitStartTS			= 0;
	u64 SplitStartPCAPTS		= 0;
	FILE* OutFile 				= NULL;


	// no no targettime rounderup was specified use default 1/4
	if (TargetTimeRoundup == 0)
	{
		TargetTimeRoundup		=  TargetTime/4; 
	}


	u64 LastPCAPTS				= 0;
	u64 SplitTS					= 0;				// next boudnary condition
	u64 LastSplitTS				= 0;				// last boundary condition 

	u8* 			Pkt			= malloc(1024*1024);	
	assert(Pkt);

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
		assert(FMADChunkBuffer != NULL);
		break;
	}

	// stats
	u64 LastPrintTS 		= 0;
	u64 LastPrintByte 		= 0;
	u64 LastPrintPkt 		= 0;

	bool IsExit = false;
	while ((!IsExit) || g_SignalExit)
	{
		s64 PCAPTS;
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
				printf("Invalid packet length: %i : %s\n", PktHeader->LengthCapture, FormatTS(LastPCAPTS) );
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

			// pcap timestamp
			PCAPTS = (u64)PktHeader->Sec * ((u64)1e9) + (u64)PktHeader->NSec * TScale;
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

				int rlen = fread(FMADChunkBuffer, 1, Header.Length, FIn);
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

			PktHeader->LengthWire		= FMADPacket->LengthWire;	
			PktHeader->LengthCapture	= FMADPacket->LengthCapture;	
			PktHeader->Sec				= FMADPacket->TS / (u64)1e9;	
			PktHeader->NSec				= FMADPacket->TS % (u64)1e9;	

			// payload
			memcpy(PktHeader + 1, FMADPacket + 1, FMADPacket->LengthCapture);

			FMADChunkPktCnt++;
			FMADChunkBufferPos += sizeof(FMADPacket_t) + FMADPacket->LengthCapture;

			// pcap timestamp
			PCAPTS = (u64)PktHeader->Sec * ((u64)1e9) + (u64)PktHeader->NSec * TScale;
		}
		break;

		// lxc ring input
		#ifdef FMADIO_LXCRING
		case INPUT_MODE_LXCRING:
		{
			// fetch packet from ring without blocking
			int ret = FMADPacket_RecvV1(s_LXCRing, 
										true, 
										&PCAPTS, 
										&PktHeader->LengthWire, 
										&PktHeader->LengthCapture, 
										NULL, 
										PktHeader + 1);
			if (ret < 0)
			{
				IsExit = true;
				break;
			}
			//printf("got packet:%i\n", PktHeader->LengthWire);

			//set packet header
			PktHeader->Sec		= PCAPTS / (u64)1e9;	
			PktHeader->NSec		= PCAPTS % (u64)1e9;	
		}
		break;
		#endif

		default:
			assert(false);
			break;
		}

		//no/invalid data so break here
		if (IsExit) break;

		// init the roll period
		if (!s_RollPeriodSetup)
		{
			s_RollPeriodSetup = true;

			// calcuclate pct within the roll the packet is
			//s64 PktRollModulo = PCAPTS %  s_RollPeriod;
			//float Pct = PktRollModulo / (float)s_RollPeriod;
			//printf("roll period setup:%.3fmin  Nano Modulo:%lli Pct%:%.3f FirstPkt:%s\n", s_RollPeriod/60e9, PktRollModulo, Pct, FormatTS(PCAPTS));

			// calculat the next roll time. by adding 10% of the roll period (if pkts are slightly before roll time)
			// to the packet time and rounding up
			s_RollLocalTS = (PCAPTS + 0.10 * s_RollPeriod + s_TZOffset) / s_RollPeriod;
			s_RollLocalTS += 1; 
			s_RollLocalTS *= s_RollPeriod; 

			printf("RollTime: %lli %s\n", s_RollLocalTS, FormatTS(s_RollLocalTS));
		}

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

					u64 TS = clock_ns();

					// log the split 
					double dT = (TS - StartTS) / 1e9;
					u8 TimeStr[1024];
					clock_date_t c	= ns2clock(PCAPTS);
					sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);

					s64 SplitDT 		= TS - SplitStartTS; 
					s64 SplitPCAPDT 	= PCAPTS - SplitStartPCAPTS; 

					printf("[%.3f H][%s] %s : Finished : Split Bytes %16lli (%.3f GB) Split Pkts:%10lli WallTime:%20lli PCAPTime:%20lli\n", dT / (60*60), TimeStr, FileName, SplitByte, SplitByte / 1e9, SplitPkt, SplitDT, SplitPCAPDT);

					// run local script for every closed split
					if (s_ScriptClose)
					{
						// filename description
						u8 Desc[4096];
						GenerateDescription(Desc, OutputMode, FileName);

						// log the number of packets and total size
						u8 Cmd[4096];	
						sprintf(Cmd, "%s \"%s\" %lli %lli %lli %lli %lli %lli",  	s_ScriptCloseCmd,
																					Desc,
																					SplitByte,
																					SplitPkt,
																					SplitDT,
																					SplitPCAPDT,
																					SplitTS,
																					LastPCAPTS
						);

						printf("Script [%s]\n", Cmd);
						system(Cmd);
					}

					// rename to file name 
					RenameFile(OutputMode, FileNamePending, FileName);
				}

				// run local new script 
				if (s_ScriptNew)
				{
					printf("Script [%s]\n", s_ScriptNewCmd);
					system(s_ScriptNewCmd);
				}

				GenerateFileName(FileNameMode, FileName, OutFileName, PCAPTS, SplitTS);
				sprintf(FileNamePending, "%s.pending", FileName);

				u8 Cmd[16*1024];
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

				SplitTS		= PCAPTS;

				SplitByte 	= 0;
				SplitPkt 	= 0;
				NewSplit 	= true;
			}
			break;

		case SPLIT_MODE_TIME:
			{
				bool IsNoSplit = false;

				//if it has a roll position
				if (s_RollLocalTS != 0)
				{
					// position wrt to split time
					float Pct = (s_RollLocalTS - (PCAPTS + s_TZOffset)) / (float)s_RollPeriod;

					// overflow into the next split
					if (Pct <= 0.0)
					{
						static u64 DisablePktCnt = 0;

						//dont split let the packets bleed over
						IsNoSplit = true;

						// log only the first 10K disables 
						DisablePktCnt++;
						if (DisablePktCnt < 10000)
						{
							printf("Disable splitter:%f : %lli %lli %lli\n", Pct, s_RollLocalTS,  (PCAPTS + s_TZOffset), s_RollPeriod, DisablePktCnt);
						}
					}
				}

				// if pcap time is over the split 
				// or the pcap time has jumped back negative substanially
				s64 dTS = PCAPTS - SplitTS;
				if (((dTS > TargetTime) || (dTS < -TargetTime))  && (!IsNoSplit))
				{
					// is it the first split
					bool IsFirstSplit = (SplitTS == 0);

					// save previous boundary
					LastSplitTS = SplitTS;

					// round up the last 1/XXX (default 4) of the time target
					// this can be overwriten with --split-time-roundup  
					// as the capture processes does not split preceisely at 0.00000000000
					// thus allow for some variance
					SplitTS = ((PCAPTS + TargetTimeRoundup) / TargetTime);
					SplitTS *= TargetTime;

					// create null PCAPs for anything missing 

					// close file and rename
					if (OutFile)
					{
						fclose(OutFile);

						u64 TS = clock_ns();

						// log the number of packets and total size
						double dT = (TS - StartTS) / 1e9;
						u8 TimeStr[1024];
						clock_date_t c	= ns2clock(PCAPTS);
						sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);


						s64 SplitDT 		= TS - SplitStartTS; 
						s64 SplitPCAPDT 	= PCAPTS - SplitStartPCAPTS; 

						printf("[%.3f H][%s] %s : Finished : Split Bytes %16lli (%.3f GB) Split Pkts:%10lli WallTime:%20lli PCAPTime:%20lli\n", dT / (60*60), TimeStr, FileName, SplitByte, SplitByte / 1e9, SplitPkt, SplitDT, SplitPCAPDT);

						// run local script for every closed split
						if (s_ScriptClose)
						{
							u8 Cmd[4096];	
							sprintf(Cmd, "%s %s %lli %lli %lli %lli %lli %lli %lli %lli %lli",
																				s_ScriptCloseCmd,
																				FileName,

																				SplitByte,
																				SplitPkt,

																				SplitDT,
																				SplitPCAPDT,

																				LastSplitTS,
																				SplitTS,

																				SplitStartPCAPTS,
																				LastPCAPTS,

																				PCAPTS
							);

							printf("Script [%s]\n", Cmd);
							system(Cmd);
						}

						// rename to file name 
						RenameFile(OutputMode, FileNamePending, FileName);

						// change open
						if (s_FileNameUID)
						{
							//fprintf(stderr, "chown\n");
							chown(FileName, s_FileNameUID, s_FileNameGID); 
						}
					}

					// run local new script 
					if (s_ScriptNew)
					{
						printf("Script [%s]\n", s_ScriptNewCmd);
						system(s_ScriptNewCmd);
					}

					// generate filename for output

					u64 SplitTSStart 	= SplitTS;
					u64 SplitTSStop		= SplitTS+TargetTime;

					GenerateFileName(FileNameMode, FileName, OutFileName, SplitTSStart, SplitTSStop);
					sprintf(FileNamePending, "%s.pending", FileName);

					// generate pipe
					u8 Cmd[4095];
					GeneratePipeCmd(Cmd, OutputMode, FileNamePending);
					printf("[%s]\n", Cmd);
					OutFile 		= popen(Cmd, "w");
					if (!OutFile)
					{
						printf("OutputFilename is invalid [%s]\n", FileName);
						break;	
					}	

					//write pcap header
					fwrite(&HeaderMaster, 1, sizeof(HeaderMaster), OutFile);	

					SplitByte 	= 0;
					SplitPkt 	= 0;
					NewSplit 	= true;
				}
			}
			break;
		}

		//if its a valid packet (e.g dont write NOP packets to disk)
		if (PktHeader->LengthWire > 0)
		{
			// optionally chomp packets before outputing
			PktHeader->LengthWire		-= s_PacketChomp; 
			PktHeader->LengthCapture	-= s_PacketChomp; 

			// write output
			int wlen = fwrite(Pkt, 1, sizeof(PCAPPacket_t) + PktHeader->LengthCapture, OutFile);
			if (wlen != sizeof(PCAPPacket_t) + PktHeader->LengthCapture)
			{
				printf("write failure. possibly out of disk space\n");
				break;
			}

			SplitByte += sizeof(PCAPPacket_t) + PktHeader->LengthCapture;
			SplitPkt  += 1; 

			TotalByte += sizeof(PCAPPacket_t) + PktHeader->LengthCapture;
			TotalPkt  += 1; 
		}	
		// use the NOP packets to update the timestamp
		LastPCAPTS = PCAPTS;

		if (NewSplit)
		{
			TotalSplit++;

			SplitStartTS		= clock_ns();
			SplitStartPCAPTS	= PCAPTS; 

			u8 TimeStr[1024];
			clock_date_t c	= ns2clock(PCAPTS);
			sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);

			double dT = (clock_ns() - StartTS) / 1e9;
			double Bps = (TotalByte * 8.0) / dT; 
			printf("[%.3f H][%s] %s : Total Bytes %.3f GB Speed: %.3f Gbps : New Split\n", dT / (60*60), TimeStr, FileName, TotalByte / 1e9, Bps / 1e9);
			fflush(stdout);
			fflush(stderr);
		}

		// assumein ~2.5Ghz clock or so, just need some periodic printing 
		if ((rdtsc() - LastTSC) > 2.5*1e9) 
		{
			LastTSC = rdtsc();

			u8 TimeStr[1024];
			clock_date_t c	= ns2clock(LastPCAPTS);
			sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);

			u64 TS = clock_ns();

			double dT 		= (TS - LastPrintTS) / 1e9; 
			double dByte 	= TotalByte - LastPrintByte; 
			double dPacket 	= TotalPkt  - LastPrintPkt; 
			double Bps 		= (dByte * 8.0) / dT; 
			double Pps 		= dPacket / dT; 
			printf("[%.3f H][%s] %s : Total Bytes %20lli %10lli %.3f GB Speed: %.3f Gbps %.3f Mpps : TotalSplit %i PCAPTS: %lli\n", dT / (60*60), 
																																	TimeStr, 
																																	FileName, 
																																	TotalByte, 
																																	TotalPkt, 
																																	TotalByte / 1e9, 
																																	Bps / 1e9, 
																																	Pps / 1e6, 
																																	TotalSplit,
																																	PCAPTS);
			fflush(stdout);
			fflush(stderr);

			LastPrintTS 	= TS;
			LastPrintByte 	= TotalByte;
			LastPrintPkt 	= TotalPkt;
		}
	}

	// final close and re-name
	if (OutFile)
	{
		fclose(OutFile);

		u64 TS = clock_ns();

		// log the number of packets and total size
		double dT = (TS - StartTS) / 1e9;
		u8 TimeStr[1024];
		clock_date_t c	= ns2clock(LastPCAPTS);
		sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);

		s64 SplitDT 		= TS - SplitStartTS; 
		s64 SplitPCAPDT 	= LastPCAPTS - SplitStartPCAPTS; 

		printf("[%.3f H][%s] %s : Finished : Split Bytes %16lli (%.3f GB) Split Pkts:%10lli WallTime:%20lli PCAPTime:%20lli close\n", dT / (60*60), TimeStr, FileName, SplitByte, SplitByte / 1e9, SplitPkt, SplitDT, SplitPCAPDT);

		// run local script for every closed split
		if (s_ScriptClose)
		{
			u8 Cmd[4096];	
			sprintf(Cmd, "%s %s %lli %lli %lli %lli %lli %lli %lli %lli %lli",
																s_ScriptCloseCmd,
																FileName,

																SplitByte,
																SplitPkt,

																SplitDT,
																SplitPCAPDT,

																LastSplitTS,
																SplitTS,

																SplitStartPCAPTS,
																LastPCAPTS,

																LastPCAPTS
			);

			printf("Script [%s]\n", Cmd);
			system(Cmd);
		}

		RenameFile(OutputMode, FileNamePending, FileName);

		// rename the last file 
		if (s_FileNameUID)
		{
			fprintf(stderr, "chown last file\n");
			chown(FileName, s_FileNameUID, s_FileNameGID); 
		}
	}

	printf("Complete\n");

	return 0;
}
