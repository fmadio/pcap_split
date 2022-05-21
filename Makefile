OBJS =
OBJS += main.o

DEF = 
DEF += -O2
DEF += --std=c99 
DEF += -D_LARGEFILE64_SOURCE 
DEF += -D_GNU_SOURCE 
DEF += -I/mnt/store0/git/

LIBS =
LIBS += -lm -lpthread

%.o: %.c
	gcc $(DEF) -c -o $@ $<

all: $(OBJS) 
	gcc -O3 -o pcap_split $(OBJS)  $(LIBS)

clean:
	rm -f $(OBJS)
	rm -f pcap_split

