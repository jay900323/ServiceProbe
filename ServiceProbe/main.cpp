#include "service_scan.h"

#define DEFAULT_CONNECT_TIMEOUT 1000
#define DEFAULT_READ_TIMEOUT 1000
#define DEFAULT_WRITE_TIMEOUT 1000

/********************   PROTOTYPES *******************/
static void servicescan_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
static void servicescan_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
static void servicescan_connect_handler(nsock_pool nsp, nsock_event nse, void *mydata);
static void end_svcprobe(nsock_pool nsp, enum serviceprobestate probe_state, ServiceGroup *SG, ServiceNFO *svc, nsock_iod nsi);


static int launchSomeServiceProbes(nsock_pool nsp, ServiceGroup *SG) {
	ServiceNFO *svc;
	ServiceProbe *nextprobe;

	size_t ss_len;
	static int warn_no_scanning = 1;

	while (SG->services_in_progress.size() < SG->ideal_parallelism &&
		!SG->services_remaining.empty()) {
		// Start executing a probe from the new list and move it to in_progress
		svc = SG->services_remaining.front();

		nextprobe = svc->nextProbe(true);

		if (nextprobe == NULL) {
			end_svcprobe(nsp, PROBESTATE_FINISHED_NOMATCH, SG, svc, NULL);
			continue;
		}

		if ((svc->niod = nsock_iod_new(nsp, svc)) == NULL) {
			printf("Failed to allocate Nsock I/O descriptor in %s()", __func__);
		}

		sockaddr_in si;
		memset(&si, 0, sizeof(si)); //每个字节都用0填充
		si.sin_family = AF_INET;
		InetPton(AF_INET, TEXT(svc->target.c_str()), &si.sin_addr.s_addr);

		if (svc->proto == IPPROTO_TCP)
			nsock_connect_tcp(nsp, svc->niod, servicescan_connect_handler,
				DEFAULT_CONNECT_TIMEOUT, svc,
				(struct sockaddr *)&si, sizeof(si),
				svc->portno);
		else {
			//assert(svc->proto == IPPROTO_UDP);
			//nsock_connect_udp(nsp, svc->niod, servicescan_connect_handler,
			//	svc, (struct sockaddr *) &ss, ss_len,
			//	svc->portno);
		}

		SG->services_remaining.pop_front();
		SG->services_in_progress.push_back(svc);
	}
	return 0;
}

static void end_svcprobe(nsock_pool nsp, enum serviceprobestate probe_state, ServiceGroup *SG, ServiceNFO *svc, nsock_iod nsi) {
	list<ServiceNFO *>::iterator member;

	svc->probe_state = probe_state;
	member = find(SG->services_in_progress.begin(), SG->services_in_progress.end(),
		svc);
	if (member != SG->services_in_progress.end()) {
		assert(*member == svc);
		SG->services_in_progress.erase(member);
	}
	else {
		/* A probe can finish from services_remaining if the host times out before the
		probe has even started */
		member = find(SG->services_remaining.begin(), SG->services_remaining.end(),
			svc);
		assert(member != SG->services_remaining.end());
		assert(*member == svc);
		SG->services_remaining.erase(member);
	}

	SG->services_finished.push_back(svc);


	if (nsi) {
		nsock_iod_delete(nsi, NSOCK_PENDING_SILENT);
	}

	return;
}

static int send_probe_text(nsock_pool nsp, nsock_iod nsi, ServiceNFO *svc,
	ServiceProbe *probe) {
	const char *probestring;
	int probestringlen;

	assert(probe);
	if (probe->isNullProbe())
		return 0; // No need to send anything for a NULL probe;
	probestring =probe->getProbeString(&probestringlen).c_str();
	assert(probestringlen > 0);
	// Now we write the string to the IOD
	nsock_write(nsp, nsi, servicescan_write_handler, DEFAULT_WRITE_TIMEOUT, svc,
		(const char *)probestring, probestringlen);
	return 0;
}

static void startNextProbe(nsock_pool nsp, nsock_iod nsi, ServiceGroup *SG,
	ServiceNFO *svc, bool alwaysrestart) {
	bool isInitial = svc->probe_state == PROBESTATE_INITIAL;
	ServiceProbe *probe = svc->currentProbe();

	// 第一个连接不会发送内容，所以第一个probe可以复用此连接
	if (!alwaysrestart && probe->isNullProbe()) {
		// The difference here is that we can reuse the same (TCP) connection
		// if the last probe was the NULL probe.
		probe = svc->nextProbe(false);
		if (probe) {
			send_probe_text(nsp, nsi, svc, probe);
			nsock_read(nsp, nsi, servicescan_read_handler, DEFAULT_READ_TIMEOUT, svc);
		}
		else {
			// Should only happen if someone has a highly perverse nmap-service-probes
			// file.  Null scan should generally never be the only probe.
			end_svcprobe(nsp, PROBESTATE_FINISHED_NOMATCH, SG, svc, NULL);
		}
	}
	else {
		//将之前的连接关闭重新再开启一个连接
		// The finisehd probe was not a NULL probe.  So we close the
		// connection, and if further probes are available, we launch the
		// next one.
		if (!isInitial)
			probe = svc->nextProbe(true); // if was initial, currentProbe() returned the right one to execute.
		if (probe) {
			// For a TCP probe, we start by requesting a new connection to the target
			if (svc->proto == IPPROTO_TCP) {
				nsock_iod_delete(nsi, NSOCK_PENDING_SILENT);
				if ((svc->niod = nsock_iod_new(nsp, svc)) == NULL) {
					printf("Failed to allocate Nsock I/O descriptor in %s()", __func__);
				}
				
				sockaddr_in si;
				memset(&si, 0, sizeof(si)); //每个字节都用0填充
				si.sin_family = AF_INET;
				InetPton(AF_INET, TEXT(svc->target.c_str()), &si.sin_addr.s_addr);

				nsock_connect_tcp(nsp, svc->niod, servicescan_connect_handler,
					DEFAULT_CONNECT_TIMEOUT, svc,
					(struct sockaddr *) &si, sizeof(si),
					svc->portno);

			}
			else {
				// TODO UDP
			}
		}
		else {
			printf("probe is NULL\n");
			// No more probes remaining!  Failed to match
			nsock_iod_delete(nsi, NSOCK_PENDING_SILENT);
			end_svcprobe(nsp, PROBESTATE_FINISHED_NOMATCH, SG, svc, NULL);
		}
	}
	return;
}

static void servicescan_connect_handler(nsock_pool nsp, nsock_event nse, void* mydata)
{
	nsock_iod nsi = nse_iod(nse);
	enum nse_status status = nse_status(nse);
	enum nse_type type = nse_type(nse);
	ServiceNFO* svc = (ServiceNFO*)mydata;
	ServiceProbe *probe = svc->currentProbe();
	ServiceGroup *SG = (ServiceGroup *)nsock_pool_get_udata(nsp);

	assert(type == NSE_TYPE_CONNECT || type == NSE_TYPE_CONNECT_SSL);
	if (status == NSE_STATUS_SUCCESS)
	{
		send_probe_text(nsp, nsi, svc, probe);
		nsock_read(nsp, nsi, servicescan_read_handler, DEFAULT_READ_TIMEOUT, svc);
	}
	else
	{
		printf("servicescan_connect_handler error  %d \n", svc->portno);
		end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
	}

	launchSomeServiceProbes(nsp, SG);
}

static void servicescan_write_handler(nsock_pool nsp, nsock_event nse, void* mydata)
{
	enum nse_status status = nse_status(nse);
	nsock_iod nsi;
	ServiceNFO *svc = (ServiceNFO *)mydata;
	ServiceGroup *SG;
	int err;

	SG = (ServiceGroup *)nsock_pool_get_udata(nsp);
	nsi = nse_iod(nse);


	if (status == NSE_STATUS_SUCCESS)
		return;

	if (status == NSE_STATUS_KILL) {
		printf("servicescan_write_handler error NSE_STATUS_KILL\n");
		end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
		return;
	}

	if (status == NSE_STATUS_ERROR) {
		err = nse_errorcode(nse);
		printf("Got nsock WRITE error #%d (%s)", err, strerror(err));
	}

	end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);

	// We may have room for more pr0bes!
	launchSomeServiceProbes(nsp, SG);

	return;
}

static void servicescan_read_handler(nsock_pool nsp, nsock_event nse, void* mydata)
{
	enum nse_status status = nse_status(nse);
	enum nse_type type = nse_type(nse);
	nsock_iod nsi = nse_iod(nse);
	ServiceNFO* svc = (ServiceNFO*)mydata;
	ServiceGroup *SG;
	int err;
	const u8* readstr;
	int readstrlen;

	SG = (ServiceGroup *)nsock_pool_get_udata(nsp);
	ServiceProbe *probe = svc->currentProbe();

	if (status == NSE_STATUS_SUCCESS)
	{
		readstr = (u8*)nse_readbuf(nse, &readstrlen);

		const struct MatchDetails *MD = probe->testMatch(readstr, readstrlen);
		if (MD) {
			//匹配成功

			printf("端口:%d  服务名:%s\n", svc->portno, MD->serviceName);
			end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
		}
		else {
			startNextProbe(nsp, nsi, SG, svc, false);
		}
	}
	else if (status == NSE_STATUS_TIMEOUT) {
		printf("servicescan_read_handler error NSE_STATUS_TIMEOUT %d   %s \n", svc->portno, probe->getName().c_str());
		startNextProbe(nsp, nsi, SG, svc, false);
	}
	else if (status == NSE_STATUS_EOF) {
		printf("servicescan_read_handler error NSE_STATUS_EOF\n");
		readstr = (u8*)nse_readbuf(nse, &readstrlen);
		if (probe->isNullProbe() && readstrlen == 0) {
			end_svcprobe(nsp, PROBESTATE_FINISHED_TCPWRAPPED, SG, svc, nsi);
		}
		else {
			startNextProbe(nsp, nsi, SG, svc, true);
		}
	}
	else if (status == NSE_STATUS_KILL) {
		printf("servicescan_read_handler error NSE_STATUS_KILL\n");
		end_svcprobe(nsp, PROBESTATE_INCOMPLETE, SG, svc, nsi);
	}
	else {
		err = nse_errorcode(nse);
		printf("Got nsock READ error #%d (%s) port=%d, servicename=%s\n", err, strerror(err), svc->portno, probe->getName().c_str());
		//printf("servicescan_read_handler error NSE_STATUS_ERROR %d   port: %d %s\n", status, svc->portno , probe->getName().c_str());
		startNextProbe(nsp, nsi, SG, svc, true);
	}

	launchSomeServiceProbes(nsp, SG);
}

int main(int argc, char *argv[])
{
	AllProbes *AP;
	AP = AllProbes::service_scan_init();
	std::vector<ServiceProbe *>::iterator vi;

	std::string target = "127.0.0.1";
	vector<unsigned int> target_port = { 80, 81,135, 445, 902, 912, 1080, 1081, 1900, 3306, 3389, 5357, 8000, 49152 };
	ServiceGroup *SG = new ServiceGroup(target, target_port, AP);

	if (SG->services_remaining.size() == 0) {
		delete SG;
		return 1;
	}

	nsock_pool nsp;
	enum nsock_loopstatus looprc;
	if ((nsp = nsp = nsock_pool_new(SG)) == NULL) {
		return 0;
	}

	launchSomeServiceProbes(nsp, SG);
	
	looprc = nsock_loop(nsp, -1);
	if (looprc == NSOCK_LOOP_ERROR) {
		int err = nsock_pool_get_error(nsp);
		printf("Unexpected nsock_loop error.  Error code %d (%s)", err, strerror(err));
	}

	nsock_pool_delete(nsp);
}