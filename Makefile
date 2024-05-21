CFLAGS = -Wall -std=c++17
LDFLAGS = -lpcap

TARGETS = udpfwd

.PHONY: all clean

all: $(TARGETS)

udpfwd: udpfwd.cc
	clang++ -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf $(TARGETS)
