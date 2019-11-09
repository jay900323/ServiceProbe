#pragma once
#include <list>
#include <vector>
#include <string>
#include "nsock/nsock.h"
#include "service_probes.h"

using namespace std;

enum serviceprobestate {
	PROBESTATE_INITIAL = 1, // No probes started yet
	PROBESTATE_NULLPROBE, // Is working on the NULL Probe
	PROBESTATE_MATCHINGPROBES, // Is doing matching probe(s)
	PROBESTATE_NONMATCHINGPROBES, // The above failed, is checking nonmatches
	PROBESTATE_FINISHED_HARDMATCHED, // Yay!  Found a match
	PROBESTATE_FINISHED_SOFTMATCHED, // Well, a soft match anyway
	PROBESTATE_FINISHED_NOMATCH, // D'oh!  Failed to find the service.
	PROBESTATE_FINISHED_TCPWRAPPED, // We think the port is blocked via tcpwrappers
	PROBESTATE_EXCLUDED, // The port has been excluded from the scan
	PROBESTATE_INCOMPLETE // failed to complete (error, host timeout, etc.)
};

class ServiceNFO {
public:
	ServiceNFO(AllProbes *AP);
	~ServiceNFO();

	ServiceProbe *currentProbe();
	ServiceProbe *nextProbe(bool newresp);
	void resetProbes(bool freefp);

	char product_matched[80];
	char version_matched[80];
	char extrainfo_matched[256];
	char hostname_matched[80];
	char ostype_matched[32];
	char devicetype_matched[32];

	nsock_iod niod; // The IO Descriptor being used in this probe (or NULL)
	std::string target;
	enum serviceprobestate probe_state; // defined in portlist.h
	vector<ServiceProbe *>::iterator current_probe;
	u16 portno; // in host byte order
	u8 proto; // IPPROTO_TCP or IPPROTO_UDP
	AllProbes *AP;

};

class ServiceGroup
{
public:
	ServiceGroup(std::string target, std::vector<unsigned int> ports, AllProbes *AP);
	~ServiceGroup();
	std::list<ServiceNFO *> services_finished; // Services finished (discovered or not)
	std::list<ServiceNFO *> services_in_progress; // Services currently being probed
	std::list<ServiceNFO *> services_remaining; // Probes not started yet
	unsigned int ideal_parallelism;
};