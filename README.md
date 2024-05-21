# udpfwd
Forward UDP packets captured by libpcap.

This command-line tool leverages the functionality of libpcap to facilitate the forwarding of filtered UDP packets without affecting the original UDP data flow.

The third-party source code `argparse.hpp` is involved for the advantage of parsing arguments.

For performance, a simple pre-allocated ring-buffer is used in the program to avoid continually malloc and free memory.

## Build
```bash
make
```

Then `udpfwd` is built. See `Makefile` for details.

## Usage
See the help message with the `-h` option:
```bash
$ ./udpfwd -h
```

## Test
Terminal-1:
```bash
# Send UDP packets from 9000 to 9001.
$ ./test/test.py
```

Terminal-2:
```bash
# Forward UDP packets (filtered by dst port 9001) to 9002.
$ ./test/udpfwd.sh
```

Terminal-3:
```bash
# Listen to UDP port 9002 and print the content onto stdout.
$ ./test/nc.sh
```

Terminal-4 (optional):
```bash
# Use tcpdump to capture the UDP packets going to port 9002.
$ ./test/tcpdump.sh
```

## Dependencies

### libpcap
```bash
# On Ubuntu
sudo apt install libpcap-dev

# On macOS
brew install libpcap
```

### clang++
- `clang++` is the default C++ compiler on macOS.
- On Ubuntu, install clang++ with the following cmdline.
```bash
sudo apt install llvm clang
```

### argparse.hpp
The `argparse.hpp` file under the top directory is simply copied from [p-ranav/argparse](https://github.com/p-ranav/argparse), which is a good C++ argument parser.
