#include <arpa/inet.h>
#include <assert.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <netinet/ip.h>
#else
#include <netinet/ether.h>
#endif

#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

#include "argparse.hpp"

//=============================================================================

#define LOG_LVL_SILENT  0
#define LOG_LVL_ERROR   1
#define LOG_LVL_WARN    2
#define LOG_LVL_INFO    3
#define LOG_LVL_DEBUG   4
#define LOG_LVL_VERBOSE 5

#define LOG_MODE_RAW    0
#define LOG_MODE_TSONLY 1
#define LOG_MODE_FULL   2

#define LOG_FMT_TIMESTAMP       "[%02d/%02d-%02d:%02d:%02d.%06ld]"
#define LOG_FMTARGS_TIMESTAMP   now.tm_mon+1, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec, (long)tv.tv_usec
#define LOG_FMT_LOGLEVEL        "%s"
#define LOG_FMT_LINE            "%s() %d"
#define LOG_FMTARGS_LINE        __FUNCTION__, __LINE__

extern int g_log_mode;
extern int g_log_level;

inline static const char* loglevel_str(int level) {
    switch (level) {
    case LOG_LVL_SILENT:  return "";
    case LOG_LVL_ERROR:   return "E";
    case LOG_LVL_WARN:    return "W";
    case LOG_LVL_INFO:    return "I";
    case LOG_LVL_DEBUG:   return "D";
    case LOG_LVL_VERBOSE: return "V";
    default:              return "?";
    }
}

#define log_raw(fmt, args...) \
    do { \
        fprintf(stdout, fmt, ##args); \
        fflush(stdout); \
    } while (0)

#define log(level, fmt, args...) \
    do { \
        if (g_log_level < level) break; \
        struct timeval tv; \
        struct tm now; \
        gettimeofday(&tv, nullptr); \
        localtime_r(&tv.tv_sec, &now); \
        if (g_log_mode == LOG_MODE_RAW) { \
            log_raw(fmt "\n", ##args); \
        } else if (g_log_mode == LOG_MODE_TSONLY) { \
            log_raw(LOG_FMT_TIMESTAMP LOG_FMT_LOGLEVEL " " fmt "\n", \
                LOG_FMTARGS_TIMESTAMP, loglevel_str(level), ##args); \
        } else if (g_log_mode == LOG_MODE_FULL) { \
            log_raw(LOG_FMT_TIMESTAMP LOG_FMT_LOGLEVEL " " LOG_FMT_LINE ": " fmt "\n", \
                LOG_FMTARGS_TIMESTAMP, loglevel_str(level), LOG_FMTARGS_LINE, ##args); \
        } \
    } while (0)

#define loge(fmt, args...) log(LOG_LVL_ERROR,   fmt, ##args)
#define logw(fmt, args...) log(LOG_LVL_WARN,    fmt, ##args)
#define logi(fmt, args...) log(LOG_LVL_INFO,    fmt, ##args)
#define logd(fmt, args...) log(LOG_LVL_DEBUG,   fmt, ##args)
#define logv(fmt, args...) log(LOG_LVL_VERBOSE, fmt, ##args)

//=============================================================================

uint32_t platform_ip_version(const void* ptr) {
#ifdef __APPLE__
    return ((const struct ip *)ptr)->ip_v;
#else
    return ((const struct iphdr *)ptr)->version;
#endif
}

uint32_t platform_ip_bytes(const void* ptr) {
#ifdef __APPLE__
    return ((const struct ip *)ptr)->ip_hl * 4;
#else
    return ((const struct iphdr *)ptr)->ihl * 4;
#endif
}

uint32_t platform_ip_protocol(const void* ptr) {
#ifdef __APPLE__
    return ((const struct ip *)ptr)->ip_p;
#else
    return ((const struct iphdr *)ptr)->protocol;
#endif
}

uint32_t platform_ip_saddr(const void* ptr) {
#ifdef __APPLE__
    return ((const struct ip *)ptr)->ip_src.s_addr;
#else
    return ((const struct iphdr *)ptr)->saddr;
#endif
}

uint32_t platform_ip_daddr(const void* ptr) {
#ifdef __APPLE__
    return ((const struct ip *)ptr)->ip_dst.s_addr;
#else
    return ((const struct iphdr *)ptr)->daddr;
#endif
}

uint32_t platform_udp_data_bytes(const void* ptr) {
#ifdef __APPLE__
    return ntohs(((const struct udphdr *)ptr)->uh_ulen);
#else
    return ntohs(((const struct udphdr *)ptr)->len);
#endif
}

uint32_t platform_udp_sport(const void* ptr) {
#ifdef __APPLE__
    return ntohs(((const struct udphdr *)ptr)->uh_sport);
#else
    return ntohs(((const struct udphdr *)ptr)->source);
#endif
}

uint32_t platform_udp_dport(const void* ptr) {
#ifdef __APPLE__
    return ntohs(((const struct udphdr *)ptr)->uh_dport);
#else
    return ntohs(((const struct udphdr *)ptr)->dest);
#endif
}

//=============================================================================

// like python str.join()
std::string join(const std::vector<std::string>& strings, const std::string& delimiter) {
    if (strings.empty()) return "";
    std::ostringstream result;
    std::copy(strings.begin(), strings.end()-1, std::ostream_iterator<std::string>(result, delimiter.c_str()));
    result << strings.end()[-1];
    return result.str();
}

// like python str.split()
std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

class MyArgs {
public:
    int loglevel;
    bool list;
    std::string interface;
    std::vector<std::string> output;
    std::string expression;
    std::vector<struct sockaddr_in> forward_addrs;

    static MyArgs ParseArgs(int argc, char *argv[]) {
        argparse::ArgumentParser parser("udpfwd", "1.1.0");
        parser.add_argument("--loglevel").metavar("LEVEL").default_value(3).scan<'i', int>()
            .help("Log level: 0-silent, 1-error, 2-warn, 3-info, 4-debug, 5-verbose.");
        parser.add_argument("-l", "--list").flag()
            .help("List all network interfaces which has IPv4 address.");
        parser.add_argument("-i", "--interface").metavar("INTERFACE")
            .help("Network interface name.");
        parser.add_argument("-o", "--output").metavar("[IP:]PORT").append()
            .help("Forward destinations.");
        parser.add_argument("EXPRESSION").remaining()
            .help("Expression of the pcap filter.");
        try {
            parser.parse_args(argc, argv);
        } catch (const std::runtime_error& err) {
            std::cout << err.what() << std::endl << std::endl;
            std::cout << parser;
            exit(1);
        }
        MyArgs args;
        args.loglevel = parser.get<int>("--loglevel");
        args.list = parser.get<bool>("--list");
        if (args.list) { // list network interfaces is an immediate-exit action, no need further parse.
            return args;
        }
        try { // parse other arguments.
            args.expression = join(parser.get<std::vector<std::string>>("EXPRESSION"), " ");
            args.interface = parser.get<std::string>("--interface");
            args.output = parser.get<std::vector<std::string>>("--output");
            if (args.output.size() == 0) {
                throw std::logic_error("No value provided for '--output'.");
            }
        } catch (const std::logic_error& err) {
            std::cout << err.what() << std::endl << std::endl;
            std::cout << parser;
            exit(1);
        }
        // parse forward destinations from the output addresses.
        for (auto& addr_str : args.output) {
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            auto parts = split(addr_str, ':');
            if (parts.size() == 2) {  // ip:port
                addr.sin_addr.s_addr = inet_addr(parts[0].c_str());
                parts.erase(parts.begin());  // left port only.
            }
            char *end = nullptr;
            long port = strtol(parts[0].c_str(), &end, 10);
            bool invalid_format = parts.size() != 1;
            bool invalid_addr = addr.sin_addr.s_addr == INADDR_NONE;
            bool invalid_port = (port <= 0 || port > 65535) || (end && *end != '\0');
            if (invalid_format || invalid_addr || invalid_port) {
                std::cout << "Invalid output address: " << addr_str << std::endl << std::endl;
                std::cout << parser;
                exit(1);
            }
            addr.sin_port = htons((short)port);
            args.forward_addrs.push_back(addr);
        }
        return args;
    }
};

class MyRingBuffer {
public:
    static constexpr int kPcapSnapLen = 1024 * 10; // max MTU is 9000, so 10KB is enough.

    explicit MyRingBuffer(size_t capacity): capacity_(capacity) {
        if (capacity_ <= 0) { capacity_ = 1; }
        logi("MyRingBuffer capacity: %zu", capacity_);
        buffer_ = std::vector<std::vector<uint8_t>>(capacity_);
        for (auto& vec : buffer_) { vec.reserve(kPcapSnapLen); }
    }

    bool Empty() {
        std::lock_guard<std::mutex> lock(mtx_);
        return size_ == 0;
    }

    bool Full() {
        std::lock_guard<std::mutex> lock(mtx_);
        return size_ == capacity_;
    }

    void Push(const uint8_t* data, size_t len, bool blocking = false) {
        std::unique_lock<std::mutex> lock(mtx_);
        if (size_ == capacity_) {
            if (blocking) {
                cv_.wait(lock, [this] { return size_ < capacity_; });
            } else {
                // drop the oldest one.
                head_ = (head_ + 1) % capacity_;
                size_--;
                logw("MyRingBuffer is full, drop the oldest one.");
            }
        }
        std::vector<uint8_t>& ref = buffer_[tail_];
        buffer_[tail_].resize(len);
        tail_ = (tail_ + 1) % capacity_;
        size_++;
        cv_.notify_one();
        lock.unlock(); // unlock before memcpy.
        if (len > 0) { // data is nullable when len is 0.
            memcpy(ref.data(), data, len);
        }
    }

    std::vector<uint8_t>& Pop() {
        std::unique_lock<std::mutex> lock(mtx_);
        if (size_ == 0) {
            cv_.wait(lock, [this] { return size_ > 0; });
        }
        std::vector<uint8_t>& ref = buffer_[head_];
        head_ = (head_ + 1) % capacity_;
        size_--;
        return ref;
    }

private:
    size_t capacity_ = 0;
    std::vector<std::vector<uint8_t>> buffer_;
    size_t head_ = 0;
    size_t tail_ = 0;
    size_t size_ = 0;
    std::mutex mtx_;
    std::condition_variable cv_;
};

class UdpFwd {
public:
    struct udp_payload {
        int len;
        char* data;
    };

    UdpFwd(const MyArgs& args) : args_(args) {}
    virtual ~UdpFwd();
    bool Initialize();
    int Run();
    void Stop();

    static void PrintInterfaces();

private:
    void HandleUdpPacket();
    void OnPacketReceived(const struct pcap_pkthdr *header, const uint8_t *packet);

    static void OnPacketReceivedStatic(uint8_t *user, const struct pcap_pkthdr *header, const uint8_t *packet) {
        ((UdpFwd*)user)->OnPacketReceived(header, packet);
    }

    MyArgs args_;
    pcap_t *pcap_ = nullptr;
    struct bpf_program bpf_ = {0, nullptr};
    int datalink_type_ = 0;
    std::map<struct sockaddr_in*, int> output_socks_;
    MyRingBuffer ring_buffer_ = MyRingBuffer(100);
};

UdpFwd::~UdpFwd() {
    for (auto& pair : output_socks_) { close(pair.second); }
    pcap_freecode(&bpf_);
    if (pcap_) { pcap_close(pcap_); }
}

bool UdpFwd::Initialize() {
    // Create output sockets.
    for (auto& addr : args_.forward_addrs) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            loge("error: socket() failed: %s", strerror(errno));
            return false;
        }
        output_socks_[&addr] = sock;
    }

    // Initialize pcap.
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    int err = 0;

#define FAIL_IF(assume_exp, fmt, args...) \
    do { if (assume_exp) { loge(fmt, ##args); return false; } } while (0)

    err = pcap_lookupnet(args_.interface.c_str(), &net, &mask, errbuf);
    FAIL_IF(err, "error: pcap_lookupnet(%s) failed(%d): %s", args_.interface.c_str(), err, errbuf);

    pcap_ = pcap_create(args_.interface.c_str(), errbuf);
    FAIL_IF(!pcap_, "error: pcap_create(%s) failed: %s", args_.interface.c_str(), errbuf);

    err = pcap_set_snaplen(pcap_, MyRingBuffer::kPcapSnapLen);
    FAIL_IF(err, "error: pcap_set_snaplen(%d) failed(%d): %s", MyRingBuffer::kPcapSnapLen, err, pcap_geterr(pcap_));

    err = pcap_set_promisc(pcap_, 0);
    FAIL_IF(err, "error: pcap_set_promisc(%d) failed(%d): %s", 0, err, pcap_geterr(pcap_));

    err = pcap_set_immediate_mode(pcap_, 1);
    FAIL_IF(err, "error: pcap_set_immediate_mode(%d) failed(%d): %s", 1, err, pcap_geterr(pcap_));

    err = pcap_set_timeout(pcap_, 1000);
    FAIL_IF(err, "error: pcap_set_timeout(%d) failed(%d): %s", 1000, err, pcap_geterr(pcap_));

    // NOTE this function needs root permission.
    err = pcap_activate(pcap_);
    FAIL_IF(err, "error: pcap_activate() failed(%d): %s", err, pcap_geterr(pcap_));

    err = pcap_compile(pcap_, &bpf_, args_.expression.c_str(), 0, mask);
    FAIL_IF(err, "error: pcap_compile(%s) failed(%d): %s", args_.expression.c_str(), err, pcap_geterr(pcap_));

    err = pcap_setfilter(pcap_, &bpf_);
    FAIL_IF(err, "error: pcap_setfilter() failed(%d): %s", err, pcap_geterr(pcap_));

    datalink_type_ = pcap_datalink(pcap_);

#undef CHECK
    return true;
}

void UdpFwd::HandleUdpPacket() {
    while (true) {
        auto payload = ring_buffer_.Pop();
        if (payload.size() == 0) { break; }
        // forward to each destination socket.
        for (auto& pair : output_socks_) {
            ssize_t n = sendto(pair.second, payload.data(), payload.size(), 0, (struct sockaddr *)pair.first, sizeof(*pair.first));
            if (n < 0) {
                const char* ip = inet_ntoa(pair.first->sin_addr);
                int port = ntohs(pair.first->sin_port);
                loge("sendto(%s:%d) failed: %d, %s", ip, port, (int)errno, strerror(errno));
            }
        }
    }
    logi("HandleUdpPacket() end.");
}

void UdpFwd::OnPacketReceived(const struct pcap_pkthdr *header, const uint8_t *packet) {
    int offset = 0;

    // handle the datalink header.
    if (datalink_type_ == DLT_NULL) {
        uint32_t protocol_type = *(uint32_t*)(packet+offset);
        if (protocol_type != 2) { logi("udp check failed"); return; }
        offset += sizeof(uint32_t);
    } else if (datalink_type_ == DLT_EN10MB) {
        if (header->caplen < (int)sizeof(struct ether_header)) { logi("udp check failed"); return; }
        const struct ether_header *eth_hdr = (const struct ether_header *)(packet+offset);
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) { logi("udp check failed"); return; }
        offset += sizeof(struct ether_header);
    } else {
        logi("OnPacketReceived: unsupported datalink type %d", datalink_type_);
        exit(1);
    }

    // handle the ip header.
    int ip_version = platform_ip_version(packet+offset);
    int ip_hdr_len_bytes = platform_ip_bytes(packet+offset);
    if (ip_version != 4) { logi("OnPacketReceived: check ip_version failed."); return; }
    if (ip_hdr_len_bytes < 20) { logi("OnPacketReceived: check ip_hdr_len_bytes failed."); return; }
    if (ip_hdr_len_bytes > 60) { logi("OnPacketReceived: check ip_hdr_len_bytes failed."); return; }
    if (platform_ip_protocol(packet+offset) != IPPROTO_UDP) { logi("OnPacketReceived: only support UDP for now."); return; }
    offset += ip_hdr_len_bytes;

    // handle the udp header.
    int udp_payload_len = platform_udp_data_bytes(packet+offset) - sizeof(struct udphdr);
    offset += sizeof(struct udphdr);
    if (header->caplen - offset != udp_payload_len) {
        logi("OnPacketReceived: unexpected UDP payload length %d (expected %d)", (header->caplen - offset), udp_payload_len);
        return;
    }
    logv("OnPacketReceived: UDP payload length %d", udp_payload_len);

    // send to the consumer.
    ring_buffer_.Push(packet+offset, udp_payload_len);
    return;
}

int UdpFwd::Run() {
    std::thread udp_packet_handler(&UdpFwd::HandleUdpPacket, this);

    int ret = pcap_loop(pcap_, -1, UdpFwd::OnPacketReceivedStatic, (u_char*)this);
    if (ret == PCAP_ERROR) {
        loge("error: pcap_loop() failed, %s", pcap_geterr(pcap_));
    } else if (ret == PCAP_ERROR_BREAK) {
        logi("pcap_loop() is broken by pcap_breakloop().");
    }

    ring_buffer_.Push(nullptr, 0, true); // notify the consumer to exit.
    udp_packet_handler.join();
    logi("UdpFwd::Run() end.");
    return 0;
}

void UdpFwd::Stop() {
    logi("stop the pcap_loop.");
    pcap_breakloop(pcap_);
}

void UdpFwd::PrintInterfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *dev_list;
    int ret;

    ret = pcap_findalldevs(&dev_list, errbuf);
    if (ret == PCAP_ERROR) {
        loge("error: pcap_findalldevs() failed, %s", errbuf);
        return;
    }

    // traverse each interface device.
    for (pcap_if_t *dev=dev_list; dev; dev=dev->next) {
        char ipv4[32] = {0};
        char nmsk[32] = {0};
        // traverse each address of the device.
        for (pcap_addr_t *addr=dev->addresses; addr; addr=addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)addr->addr;
                struct sockaddr_in *ipv4_nmsk = (struct sockaddr_in *)addr->netmask;
                strncpy(ipv4, inet_ntoa(ipv4_addr->sin_addr), 32);
                strncpy(nmsk, inet_ntoa(ipv4_nmsk->sin_addr), 32);
                break;
            }
        }
        // print ipv4 address.
        if (ipv4[0]) {
            log_raw("\nINTERFACE %s:\n", dev->name);
            log_raw("    ipv4 addr: %s\n", ipv4);
            log_raw("      netmask: %s\n", nmsk);
        }
    }

    pcap_freealldevs(dev_list);
}

int g_log_level = LOG_LVL_INFO;
int g_log_mode = LOG_MODE_FULL;

// global variable for signal handler.
static UdpFwd* g_udp_fwd = nullptr;

void signal_handler (int sig) {
    log_raw("\n");
    logw("received signal: %d", sig);
    switch (sig) {
    case SIGINT: case SIGTERM: case SIGSTOP:
        if (g_udp_fwd) { g_udp_fwd->Stop(); }
        break;
    }
}

int main(int argc, char *argv[]) {
    MyArgs args = MyArgs::ParseArgs(argc, argv);
    if (args.list) {
        UdpFwd::PrintInterfaces();
        return 0;
    }

    g_log_level = args.loglevel;
    logi("loglevel: %d", args.loglevel);
    logi("list: %d", args.list);
    logi("interface: %s", args.interface.c_str());
    logi("output: %s", join(args.output, ", ").c_str());
    logi("expression: %s", args.expression.c_str());

    UdpFwd udpfwd(args);
    if (!udpfwd.Initialize()) {
        loge("Error: udpfwd.Initialize() failed.");
        return 1;
    }

    g_udp_fwd = &udpfwd;
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, signal_handler);

    return udpfwd.Run();
}
