#include "service_probes.h"
#include "cjson/cJSON.h"
#include "pcre/pcre.h"
#include "utils.h"
#include "nmap_service_probes.h"

int parse_nmap_service_probe(AllProbes *AP);

ServiceProbeMatch::ServiceProbeMatch()
{

}

ServiceProbeMatch::~ServiceProbeMatch()
{

}

typedef int (*match_filter_callback)(cJSON *sname_node, void *value);

typedef struct probe_match_filter
{
	const char *sname;
	void *value;
	match_filter_callback fcall;
};

void merge_probe_match_filter(cJSON *match, std::vector<probe_match_filter> &match_filter_vct)
{
	if (!match)
		return;

	for (int i = 0; i < match_filter_vct.size(); i++) {
		cJSON *json = cJSON_GetObjectItem(match, match_filter_vct[i].sname);
		if (json) {
			if (match, match_filter_vct[i].fcall) {
				match_filter_vct[i].fcall(json, &match_filter_vct[i].value);
			}
			else {
				//默认当做字符串处理
				*(std::string *)match_filter_vct[i].value = json->valuestring;
			}
		}
	}
}

int match_compile_regex(cJSON *sname_node, void *value)
{
	pcre* pre;
	int options;
	const char* error;
	int errorOffset;
	options = PCRE_CASELESS | PCRE_MULTILINE;
	pre = pcre_compile(sname_node->valuestring, options, &error, &errorOffset, NULL);
	if (pre != NULL)
	{
		**(pcre ***)value = pre;
		return 0;
	}
	return 1;
}

void ServiceProbeMatch::InitMatch(cJSON *match, int lineno)
{

	std::vector<probe_match_filter> match_filter_vct = {
		{ "name", &servicename, NULL },
		{ "match", &matchstr, NULL },
		{ "p", &product_template, NULL },
		{ "v", &version_template, NULL },
		{ "i", &info_template, NULL },
		{ "h", &hostname_template, NULL },
		{ "o", &ostype_template, NULL },
		{ "d", &devicetype_template, NULL },
		{ "cpe", &cpe_template, NULL },
		{ "match", &regex_compiled, match_compile_regex }
	};
	merge_probe_match_filter(match, match_filter_vct);
}

const struct MatchDetails *ServiceProbeMatch::testMatch(const u8 *buf, int buflen)
{
	int rc;
	int i;
	static char product[80];
	static char version[80];
	static char info[256];  /* We will truncate with ... later */
	static char hostname[80];
	static char ostype[32];
	static char devicetype[32];
	char *bufc = (char *)buf;
	int ovector[150]; // allows 50 substring matches (including the overall match)

	rc = pcre_exec(regex_compiled, NULL, bufc, buflen, 0, 0, ovector, sizeof(ovector) / sizeof(*ovector));

	if (rc > 0)
	{
		MatchDetails *MD = new MatchDetails;
		MD->serviceName = servicename.c_str();
		return MD;
	}
	return NULL;
}

ServiceProbe::ServiceProbe()
{

}

ServiceProbe::~ServiceProbe()
{

}

void ServiceProbe::setProbeDetails(cJSON *probe, int lineno)
{
	cJSON* probe_name = cJSON_GetObjectItem(probe, "probe_name");
	this->probename = probe_name->valuestring;
	this->probeprotocol = IPPROTO_TCP;

	cJSON* probestr = cJSON_GetObjectItem(probe, "probe");
	unsigned int probe_len = strlen(probestr->valuestring);
	probestringlen = probe_len;
	setProbeString(cstring_unescape(probestr->valuestring, &probe_len), probe_len);

}

void ServiceProbe::InitProbe(cJSON *probe, int lineno)
{
	//probe基本信息读取
	setProbeDetails(probe, lineno);

	//probe端口信息读取
	cJSON* ports = cJSON_GetObjectItem(probe, "ports");
	setPortVector(ports);

	cJSON* matchs = cJSON_GetObjectItem(probe, "matchs");
	int matchs_size = cJSON_GetArraySize(matchs);
	for (int j = 0; j < matchs_size; ++j)
	{
		cJSON* match = cJSON_GetArrayItem(matchs, j);
		addMatch(match, 0);
	}
}

void ServiceProbe::addMatch(cJSON *match, int lineno)
{
	if (match) {
		ServiceProbeMatch *probe_match = new ServiceProbeMatch;
		probe_match->InitMatch(match, lineno);
		matches.push_back(probe_match);
	}
}

const struct MatchDetails *ServiceProbe::testMatch(const u8 *buf, int buflen)
{
	std::vector<ServiceProbeMatch *>::iterator vi;
	const struct MatchDetails *MD;

	for (vi = matches.begin(); vi != matches.end(); vi++) {
		MD = (*vi)->testMatch(buf, buflen);
		if (MD && MD->serviceName)
			return MD;
	}

	return NULL;
}


bool ServiceProbe::portIsProbable(unsigned int port)
{
	for (int i = 0; i < probableports.size(); i++) {
		if (port == probableports[i]) {
			return true;
		}
	}
	return false;
}

void ServiceProbe::setProbeString(char *ps, int stringlen)
{
	probestring.assign(ps, stringlen);
}

void ServiceProbe::setPortVector(cJSON *ports)
{
	int ports_size = cJSON_GetArraySize(ports);
	for (int j = 0; j < ports_size; ++j)
	{
		cJSON* port = cJSON_GetArrayItem(ports, j);
		std::string portstr = port->valuestring;
		if (portstr.find("-") != std::string::npos)  {
			std::vector<std::string> portstr_v = split(portstr, "-");
			if (portstr_v.size() == 2) {
				for (int k = stoi(portstr_v[0]); k <= stoi(portstr_v[1]); ++k) {
					probableports.push_back(k);
				}
			}
		}
		else {
			probableports.push_back(atoi(port->valuestring));
		}
	}
}

AllProbes::AllProbes()
{

}

AllProbes::~AllProbes()
{

}

AllProbes *AllProbes::global_AP;
AllProbes *AllProbes::service_scan_init(void)
{
	if (global_AP)
		return global_AP;
	global_AP = new AllProbes();
	parse_nmap_service_probe(global_AP);

	return global_AP;
}

ServiceProbe *AllProbes::getProbeByName(const char *name, int proto)
{
	std::vector<ServiceProbe *>::iterator vi;

	if (proto == IPPROTO_TCP && nullProbe && strcmp(nullProbe->getName().c_str(), name) == 0)
		return nullProbe;

	for (vi = probes.begin(); vi != probes.end(); vi++) {
		if ((*vi)->getProbeProtocol() == proto &&
			strcmp(name, (*vi)->getName().c_str()) == 0)
			return *vi;
	}

	return NULL;
}

int parse_nmap_service_probe(AllProbes *AP)
{
	cJSON* root = NULL;
	root = cJSON_Parse((const char *)nmap_service_probes_json);
	if (!root)
	{
		return 1;
	}
	cJSON* probes = cJSON_GetArrayItem(root, 0);
	int probes_count = cJSON_GetArraySize(probes);
	for (int i = 0; i < probes_count; ++i)
	{
		ServiceProbe *service_probe = new ServiceProbe;
		cJSON* item = cJSON_GetArrayItem(probes, i);
		service_probe->InitProbe(item, 0);

		if (service_probe->isNullProbe()) {
			AP->nullProbe = service_probe;
		}
		else {
			AP->probes.push_back(service_probe);
		}
	}
	cJSON_Delete(root);
	return 0;
}