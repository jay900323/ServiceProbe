#include "service_scan.h"


ServiceNFO::ServiceNFO(AllProbes *newAP)
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	AP = newAP;
	probe_state = PROBESTATE_INITIAL;
}


ServiceNFO::~ServiceNFO()
{

}

ServiceProbe *ServiceNFO::nextProbe(bool newresp)
{
	bool dropdown = false;

	if (probe_state == PROBESTATE_INITIAL) {
		probe_state = PROBESTATE_NULLPROBE;
		// This is the very first probe -- so we try to use the NULL probe
		// but obviously NULL probe only works with TCP
		if (proto == IPPROTO_TCP && AP->nullProbe)
			return AP->nullProbe;

		// No valid NULL probe -- we'll drop to the next state
	}

	if (probe_state == PROBESTATE_NULLPROBE) {
		// There can only be one (or zero) NULL probe.  So now we go through the
		// list looking for matching probes
		probe_state = PROBESTATE_MATCHINGPROBES;
		dropdown = true;
		current_probe = AP->probes.begin();
	}

	if (probe_state == PROBESTATE_MATCHINGPROBES) {
		if (!dropdown && current_probe != AP->probes.end()) current_probe++;
		while (current_probe != AP->probes.end()) {
			// For the first run, we only do probes that match this port number
			if ((proto == (*current_probe)->getProbeProtocol()) &&
				(*current_probe)->portIsProbable(portno)) {
				// This appears to be a valid probe.  Let's do it!
				return *current_probe;
			}
			current_probe++;
		}
		// Tried all MATCHINGPROBES -- now we must move to nonmatching
		probe_state = PROBESTATE_NONMATCHINGPROBES;
		dropdown = true;
		current_probe = AP->probes.begin();
	}

	if (probe_state == PROBESTATE_NONMATCHINGPROBES) {
		if (!dropdown && current_probe != AP->probes.end()) current_probe++;
		while (current_probe != AP->probes.end()) {
			// The protocol must be right, it must be a nonmatching port ('cause we did those),
			// and we better either have no soft match yet, or the soft service match must
			// be available via this probe. Also, the Probe's rarity must be <= to our
			// version detection intensity level.
			if ((proto == (*current_probe)->getProbeProtocol()) &&
				!(*current_probe)->portIsProbable(portno)) {
				// Valid, probe.  Let's do it!
				return *current_probe;
			}
			current_probe++;
		}

		// Tried all NONMATCHINGPROBES -- we're finished
		probe_state = PROBESTATE_FINISHED_NOMATCH;
		return NULL;
	}

	return NULL;
}

ServiceProbe *ServiceNFO::currentProbe() {
	if (probe_state == PROBESTATE_INITIAL) {
		return nextProbe(true);
	}
	else if (probe_state == PROBESTATE_NULLPROBE) {
		assert(AP->nullProbe);
		return AP->nullProbe;
	}
	else if (probe_state == PROBESTATE_MATCHINGPROBES ||
		probe_state == PROBESTATE_NONMATCHINGPROBES) {
		return *current_probe;
	}
	return NULL;
}

void ServiceNFO::resetProbes(bool freefp)
{

}

ServiceGroup::ServiceGroup(std::string target, std::vector<unsigned int> ports, AllProbes *AP)
{
	ServiceNFO *svc;
	for (int i = 0; i < ports.size(); i++)
	{
		svc = new ServiceNFO(AP);
		svc->target = target;
		svc->portno = ports[i];
		svc->proto = IPPROTO_TCP;
		services_remaining.push_back(svc);
	}
	ideal_parallelism = 100;
}

ServiceGroup::~ServiceGroup()
{

}