/////////////////////////////////////////////////////////////////////
//
// FILE : main.cpp
// AUTHOR : 0xcds4r
// ON : 16.02.2026
//
// DESCRIPTION :
// LD_PRELOAD network hook for intercepting send() calls.
// Detects TLS ClientHello packets and allows strategy-based handling.
//
/////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////// 
// ALL HEADERS
/////////////////////////////////////////////////////////////////////
//
// dlfcn.h        -> dlsym, RTLD_NEXT (runtime symbol resolution)
// sys/socket.h   -> socket API
// sys/types.h    -> system data types
// netinet/in.h   -> internet protocol structures
// netinet/tcp.h  -> TCP options (TCP_NODELAY, TCP_MAXSEG, etc.)
// unistd.h       -> getpid()
// cstring        -> memory operations
// cstdio         -> fprintf
// cstdlib        -> getenv, atoi, srand
// time.h         -> time()
// atomic         -> thread-safe counters
// string         -> std::string support
//
//////////////////////////////////////////////////////////////////////
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <time.h>
#include <atomic>
#include <string>

/////////////////////////////////////////////////////////////////////// 
// LOG DEFINES
/////////////////////////////////////////////////////////////////////// 
//
// LOG macro:
// Prints debug output only if debug_mode is enabled.
// Prevents unnecessary fprintf calls in production mode.
//
///////////////////////////////////////////////////////////////////////
#define LOG(...) if (debug_mode) fprintf(stderr, __VA_ARGS__)

/////////////////////////////////////////////////////////////////////// 
// GLOBAL STATE
/////////////////////////////////////////////////////////////////////// 
//
// real_send      -> pointer to original libc send()
// packet_count   -> atomic counter for detected TLS packets
// debug_mode     -> enables verbose logging
// strategy       -> selected processing strategy (via env variable)
//
///////////////////////////////////////////////////////////////////////
static ssize_t (*real_send)(int sockfd, const void *buf, size_t len, int flags) = nullptr;
static std::atomic<int> packet_count{0};
static bool debug_mode = false;
static int strategy = 0;

/////////////////////////////////////////////////////////////////////// 
// CONSTRUCTOR
/////////////////////////////////////////////////////////////////////// 
//
// init():
// Runs automatically when shared object is loaded.
// Reads environment variables:
//   DPI_DEBUG     -> enable debug logging
//   DPI_STRATEGY  -> select strategy (1..3)
//
// Also seeds pseudo-random generator.
//
///////////////////////////////////////////////////////////////////////
__attribute__((constructor))
static void init() 
{
	const char* debug = getenv("DEBUG");
	debug_mode = (debug && atoi(debug) > 0);
	
	const char* strat = getenv("STRATEGY");
	strategy = strat ? atoi(strat) : 0;
	
	if (debug_mode) {
		fprintf(stderr, "[NetHook] Initialized (Strategy: %d, PID: %d)\n", 
				strategy, getpid());
	}
	
	srand(time(NULL) ^ getpid());
}

/////////////////////////////////////////////////////////////////////// 
// TLS DETECTION
/////////////////////////////////////////////////////////////////////// 
//
// is_tls_client_hello():
// Performs minimal structural validation to determine whether
// the outgoing buffer appears to contain a TLS ClientHello message.
//
// Checks:
//   - ContentType == 0x16 (Handshake)
//   - TLS version major == 0x03
//   - HandshakeType == 0x01 (ClientHello)
//
// NOTE:
// This is a heuristic check, not a full TLS parser.
//
///////////////////////////////////////////////////////////////////////
static bool is_tls_client_hello(const uint8_t* data, size_t len) 
{
	if (len < 100) return false;

	if (data[0] != 0x16) return false;  // content type - handshake
	if (data[1] != 0x03) return false;  // tls ver major
	if (data[5] != 0x01) return false;  // handshake type - ClientHello

	return true;
}

/////////////////////////////////////////////////////////////////////// 
// SNI EXTENSION SEARCH
/////////////////////////////////////////////////////////////////////// 
//
// find_sni_extension():
// Parses TLS ClientHello structure and searches for
// extension type 0x0000 (server_name).
//
// Returns:
//   Offset of extension inside buffer if found.
//   0 if not found or malformed.
//
// Parsing steps:
//   - Skip record header
//   - Skip handshake header
//   - Skip legacy version
//   - Skip random
//   - Skip session ID
//   - Skip cipher suites
//   - Skip compression methods
//   - Iterate over extensions
//
///////////////////////////////////////////////////////////////////////
static size_t find_sni_extension(const uint8_t* data, size_t len) 
{
	if (len < 50) return 0;
	size_t pos = 5;
	
	// skip handshake header (4 bytes)
	pos += 4;
	
	// skip leg ver (2 bytes)
	pos += 2;
	
	// skip random (32 bytes)
	pos += 32;
	
	// session id len
	if (pos >= len) return 0;
	uint8_t sid_len = data[pos++];
	pos += sid_len;
	
	// cipher suites len
	if (pos + 1 >= len) return 0;
	uint16_t cs_len = (data[pos] << 8) | data[pos+1];
	pos += 2 + cs_len;
	
	// compression methods len
	if (pos >= len) return 0;
	uint8_t cm_len = data[pos++];
	pos += cm_len;
	
	// ext len
	if (pos + 1 >= len) return 0;
	uint16_t ext_len = (data[pos] << 8) | data[pos+1];
	pos += 2;
	
	size_t ext_end = pos + ext_len;
	while (pos + 4 <= ext_end && pos + 4 <= len) {
		uint16_t type = (data[pos] << 8) | data[pos+1];
		uint16_t length = (data[pos+2] << 8) | data[pos+3];
		
		if (type == 0x0000) {  // server_name
			LOG("Found SNI at offset %zu\n", pos);
			return pos;
		}
		
		pos += 4 + length;
	}
	
	return 0;
}


/////////////////////////////////////////////////////////////////////// 
// STRATEGY 01
/////////////////////////////////////////////////////////////////////// 
//
// strategy_01():
// Default processing strategy.
// Currently passes data through without modification.
//
///////////////////////////////////////////////////////////////////////
static ssize_t strategy_01(int sockfd, const uint8_t* orig_data, size_t len, int flags, size_t sni_pos)
{
	return real_send(sockfd, orig_data, len, flags);
}

/////////////////////////////////////////////////////////////////////// 
// STRATEGY 02
/////////////////////////////////////////////////////////////////////// 
//
// strategy_02():
// Second processing strategy.
// Currently passes data through without modification.
//
///////////////////////////////////////////////////////////////////////
static ssize_t strategy_02(int sockfd, const uint8_t* orig_data, size_t len, int flags, size_t sni_pos)
{
	return real_send(sockfd, orig_data, len, flags);
}

/////////////////////////////////////////////////////////////////////// 
// STRATEGY 03
/////////////////////////////////////////////////////////////////////// 
//
// strategy_03():
// Third processing strategy.
// Currently passes data through without modification.
//
///////////////////////////////////////////////////////////////////////
static ssize_t strategy_03(int sockfd, const uint8_t* orig_data, size_t len, int flags, size_t sni_pos)
{
	return real_send(sockfd, orig_data, len, flags);
}

/////////////////////////////////////////////////////////////////////// 
// SEND HOOK
/////////////////////////////////////////////////////////////////////// 
//
// Overridden send() function.
//
// Workflow:
//   1. Resolve original send() via dlsym (lazy resolution)
//   2. Inspect outgoing buffer
//   3. Detect TLS ClientHello
//   4. Search for SNI extension
//   5. Apply selected strategy
//   6. Forward data to original send()
//
// If no TLS ClientHello detected,
// the call is forwarded immediately.
//
///////////////////////////////////////////////////////////////////////
extern "C" ssize_t send(int sockfd, const void *buf, size_t len, int flags) 
{
	if (!real_send) {
		real_send = (ssize_t (*)(int, const void*, size_t, int)) dlsym(RTLD_NEXT, "send");
	}
	
	const uint8_t* data = static_cast<const uint8_t*>(buf);
	
	if (!is_tls_client_hello(data, len)) {
		return real_send(sockfd, buf, len, flags);
	}
	
	int pkt_num = ++packet_count;
	LOG("[NetHook] Packet #%d: Detected TLS ClientHello (%zu bytes)\n", pkt_num, len);
	
	size_t sni_pos = find_sni_extension(data, len);

	if (sni_pos == 0) 
	{
		LOG("[NetHook] No SNI found, passing through\n");
		return real_send(sockfd, buf, len, flags);
	}
	
	int selected_strategy = strategy;

	if (selected_strategy <= 0 || selected_strategy > 3) {
		selected_strategy = 1;
	}
	
	LOG("[NetHook] Using strategy %d for packet #%d\n", selected_strategy, pkt_num);
	
	if(selected_strategy == 1) {
		return strategy_01(sockfd, data, len, flags, sni_pos);
	}
	else if(selected_strategy == 2) {
		return strategy_02(sockfd, data, len, flags, sni_pos);
	}
	else if(selected_strategy == 3) {
		return strategy_03(sockfd, data, len, flags, sni_pos);
	}

	return real_send(sockfd, buf, len, flags);
}
