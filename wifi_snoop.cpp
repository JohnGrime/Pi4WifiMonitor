/*
g++ -std=c++14 -Wall -Wextra -pedantic wifi_snoop.cpp -lpcap -lpthread

sudo ./a.out <interface> <filter>

Input filter strings are the usual pcap filters.

For device tracking, probably not a good idea to use probe requests due to
randomization of MAC addresses on iOS and Android etc. However, associate
requests, reassociate requests, and null messages related to power management
are likely to contain real MAC addresses so may be the better approach.

Note: may need to skip channels regularly, depending on use case!
*/

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>
#include <string.h>

#include "MonitorUtil.hpp"

using NodeMap = std::map<std::string,std::map<std::string,int>>;

namespace {
	volatile std::sig_atomic_t gSignalStatus = 0;

	void signal_handler(int signal)
	{
		gSignalStatus = signal;
	}

	void test_result(int s, const char *m)
	{
		if (s >= 0 ) return;
		printf("%s(): %s\n", m, pcap_statustostr(s));
		exit(-1);
	}

	void print_digest(const NodeMap &nodes, int N = 10)
	{
		if (nodes.size()<1) {
			printf("No data.\n");
			return;
		}

		printf("\n");
		for (const auto &it : nodes) {
			printf("%s:\n", it.first.c_str());
			int i = 0;
			for (const auto &it2 : it.second) {
				printf("\t%s", it2.first.c_str());
				i++;
				if (i%N==0) printf("\n");
			}
			if (i%N) printf("\n");
		}
		printf("\n");
	}
}

int main(int argc, char *argv[])
{
	const int monitor_mode = 1;
	const int snapshot_len = 2048;
	const int promisc_mode = 1;
	const int timeout_ms = 512;

	const bool use_select = true;

	std::vector<char> buf(PCAP_ERRBUF_SIZE+1);
	pcap_t *pcap;
	NodeMap nodes;
	std::mutex mutex;

	//
	// Check arguments
	//

	if (argc < 2)
	{
		printf("\n");
		printf("Usage:   %s <interface> [filter]\n", argv[0]);
		printf("Example: %s en0 \"type mgt subtype assoc-req or type data subtype NULL\"\n", argv[0]);
		printf("\n");
		exit(-1);
	}

	const char *device = argv[1];
	const char *filter = (argc>2) ? argv[2] : "";

	printf("\n");
	printf("Filtering \"%s\" with \"%s\"\n", device, filter);
	printf("%s mode.\n", use_select ? "Nonblocking" : "Blocking" );
	printf("\n");

	//
	// Set pcap parameters, activate
	//

	{
		pcap = pcap_create(device, &buf[0]);
		if (pcap == nullptr) {
			printf("pcap_create(): %s\n", &buf[0]);
			exit(-1);
		}

		test_result(pcap_set_rfmon(pcap, monitor_mode), "pcap_set_rfmon");
		test_result(pcap_set_snaplen(pcap, snapshot_len), "pcap_set_snaplen");
		test_result(pcap_set_promisc(pcap, promisc_mode), "pcap_set_promisc");
		test_result(pcap_set_timeout(pcap, timeout_ms), "pcap_set_timeout");		
		test_result(pcap_activate(pcap), "pcap_activate");
	}

	//
	// Set up filter(s)
	//

	{
		struct bpf_program fp;

		test_result(pcap_compile(pcap, &fp, filter, 0, 0), "pcap_compile");
		test_result(pcap_setfilter(pcap, &fp), "pcap_setfilter");
	}

	//
	// Note: pcap's "packet timeout" (via pcap_set_timeout()) is not
	// what you think. Certain platforms (Raspbian seems to be one) will
	// block in pcap_next() until a packet arrives, regardless of user
	// interrupts. This means the program may not quit until a packet
	// passes the filter, which can take a very long time depending on
	// your filter! Therefore, make pcap session explicitly nonblocking,
	// and use a good old select() call with a timeout in the main loop.
	//

	if (use_select)
	{
		test_result(pcap_setnonblock(pcap, 1, &buf[0]), "pcap_setnonblock");
		
		int r = pcap_getnonblock(pcap, &buf[0]);
		test_result(r, "pcap_getnonblock");
		
		if(r != 1) {
			printf("pcap_get_nonblock(): unexpected result (%d)\n", r);
			exit(-1);
		}
	}

	//
	// Signal handlers; signal() deprecated, use sigaction() if possible.
	//

	{
		struct sigaction new_action;

		new_action.sa_handler = signal_handler;
		sigemptyset(&new_action.sa_mask);
		new_action.sa_flags = 0;

		if (sigaction(SIGINT, &new_action, nullptr) != 0) {
			perror("sigaction: ");
			exit(-1);
		}
	}

	//
	// Periodic update of node information; runs on separate thread.
	// Split full pause interval into slices to catch user interrupt
	// faster; otherwise, max wait to join thread == interval.
	//

	std::thread thread( [&nodes,&mutex] {
		auto interval = 5; // seconds
		auto slice = 0.25; // seconds
		auto tics = (int)(slice * 1'000'000); // useconds
		auto N = (int) (interval / slice);
		while (true) {

			for (int i=0; i<N && gSignalStatus==0; i++) usleep(tics);
			if (gSignalStatus != 0) break;

			mutex.lock();
			print_digest(nodes);
			mutex.unlock();
		}
	});

	//
	// Watch packets until user exit.
	//

	{
		MonitorUtil::RadiotapHeader rtHdr;
		MonitorUtil::FrameHeader frmHdr;

		std::string src, dst, description;
		struct pcap_pkthdr header;

		int fd;
		fd_set fds;
		struct timeval timeout;

		if (use_select) {
			fd = pcap_get_selectable_fd(pcap);
			test_result(fd, "pcap_get_selectable_fd");
		}

		while (gSignalStatus == 0) {

			// Reset fdset and timeout, latter because some select() calls
			// modify timeval to show time remaining after select() return.
			if (use_select) {
				FD_ZERO(&fds);
				FD_SET(fd, &fds);
				timeout.tv_sec = timeout_ms / 1000;
				timeout.tv_usec = (timeout_ms % 1000) * 1000;
				auto r = select(FD_SETSIZE, &fds, nullptr, nullptr, &timeout);
				if (r < 1) continue;
			}

			auto packet = pcap_next(pcap, &header);
			if (packet) {
				// Radiotap header
				unsigned const char *ptr = (unsigned char const *)packet;
				rtHdr.Parse(ptr);


				// 802.11 header
				ptr = &ptr[rtHdr.length];
				frmHdr.Parse(ptr);

				src = MonitorUtil::ToString(frmHdr.trnAddr,buf);
				dst = MonitorUtil::ToString(frmHdr.rcvAddr,buf);
				description = MonitorUtil::FrameHeader::ControlToString(frmHdr.control);

				printf("src=%s ", src.c_str());
				printf("dst=%s ", dst.c_str());
				printf("typ=%s\n", description.c_str());

				// Should be low contention, so not a performance bottleneck.
				mutex.lock();
				nodes[description][src] = 1;
				mutex.unlock();
			}
		}
	}

	//
	// Cleanup
	//

	{
		pcap_stat s;

		printf("Cleanup! (%s)\n", strsignal(gSignalStatus));

		printf("Joining thread ...\n");
		thread.join();

		printf("Final digest:\n");
		print_digest(nodes);

		test_result(pcap_stats(pcap,&s),"pcap_stats");

		printf("received %d packets.\n", s.ps_recv);
		printf("dropped %d packets.\n", s.ps_drop);
		printf("interface/driver dropped %d packets.\n", s.ps_ifdrop);

		pcap_close(pcap);
	}

}
