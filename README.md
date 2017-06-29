# pcap_split 

![Alt text](http://fmad.io/analytics/logo_capmerge.png "fmadio flow analyzer logo")

pcap_split is a high performance TB scale pcap split utilitiy. It operats using STDIN so you can pipe data ad needed

###Options

Command line options

```
pcap_split -o <output base> -s <split type>

NOTE: Input PCAP`s are always read from STDIN

-v                         : verbose output
--split-byte  <byte count> : split by bytes

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
