# pcap_split 

![Alt text](http://firmware.fmad.io/images/logo_capmerge.png "fmadio flow analyzer logo")

[FMADIO 10G 40G 100G 400G Packet Capture](https://fmad.io)


pcap_split is a high performance TB scale pcap split utilitiy. It operats using STDIN so you can pipe data ad needed

###Options

Command line options

```
fmadio@fmadio100v2-228U:~$ pcap_split
invalid config. no split type time/bytes specified

fmadio 10G/40G/100G Packet Capture Systems (https://fmad.io)
(Thu Jun  9 21:58:23 2022)

pcap_split -o <output base> -s <split type>

NOTE: Input PCAP`s are always read from STDIN

--cpu  <cpu id>                : bind specifically to a CPU

--ring  <lxc_ring path>        : read data from fmadio lxc ring

-v                             : verbose output
--split-byte  <byte count>     : split by bytes
--split-time  <nanoseconds>    : split by time

--filename-epoch-sec           : output epoch sec  filename
--filename-epoch-sec-startend  : output epoch sec start/end filename
--filename-epoch-msec          : output epoch msec filename
--filename-epoch-usec          : output epoch usec filename
--filename-epoch-nsec          : output epoch nsec filename
--filename-tstr-HHMM           : output time string filename (Hour Min)
--filename-tstr-HHMMSS         : output time string filename (Hour Min Sec)
--filename-tstr-HHMMSS_TZ      : output time string filename (Hour Min Sec) plus timezone
--filename-tstr-HHMMSS_NS      : output time string filename (Hour Min Sec Nanos)
--filename-tstr-HHMMSS_SUB     : output time string filename (Hour Min Sec Subseconds)
--filename-strftime "string" : output time string to strftime printed string

--filename-suffix              : filename suffix (default .pcap)

--pipe-cmd                     : introduce a pipe command before final output
--rclone                       : endpoint is an rclone endpoint
--curl <args> <prefix>         : endpoint is curl via ftp
--null                         : null performance mode
-Z <username>                  : change ownership to username


example: split every 100GB
$ cat my_big_capture.pcap | pcap_split -o my_big_capture_ --split-byte 100e9

example: split every 1min
$ cat my_big_capture.pcap | pcap_split -o my_big_capture_ --split-time 60e9

example: split compress pcap every 100GB
$ gzip -d -c my_big_capture.pcap.gz | pcap_split -o my_big_capture_ --split-byte 100e9

fmadio@fmadio100v2-228U:~$
```

###Example
```
example: split every 100GB
$ cat my_big_capture.pcap | pcap_split -o my_big_capture_ --split-byte 100e9

example: split compress pcap every 100GB
$ gzip -d -c my_big_capture.pcap.gz | pcap_split -o my_big_capture_ --split-byte 100e9

```
### Support 

This tool is part of the FMADIO **10Gbe/40Gbe/100 Gbe packet capture device**, more information can be found at http://fmad.io 

Contact us for any bugs/patches/requests send a mail to: support at fmad.io 
