LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.h pcap-test.c

clean:
	rm -f pcap-test *.o
