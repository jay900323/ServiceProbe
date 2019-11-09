#ifndef _SERVICE_PROBES_H
#define _SERVICE_PROBES_H
#include "nbase.h"
#include <assert.h>
#include <vector>
#include "pcre/pcre.h"
#include "cjson/cJSON.h"

struct MatchDetails {
	// Rather the match is a "soft" service only match, where we should
	// continue to look for a better match.
	bool isSoft;

	// The service that was matched (Or NULL) zero-terminated.
	const char *serviceName;

	// The product/verson/info for the service that was matched (Or NULL)
	// zero-terminated.
	const char *product;
	const char *version;
	const char *info;

	// More information from a match. Zero-terminated strings or NULL.
	const char *hostname;
	const char *ostype;
	const char *devicetype;
};

class ServiceProbeMatch
{
public:
	ServiceProbeMatch();
	~ServiceProbeMatch();
	void InitMatch(cJSON *match, int lineno);

	const struct MatchDetails *testMatch(const u8 *buf, int buflen);
	const std::string getName() { return servicename; }
private:
	/* 服务名称 */
	std::string servicename;
	/* 正则表达式 */
	std::string matchstr;
	/* 产品名称 */
	std::string product_template;
	/* 版本号 */
	std::string version_template;
	/* 描述信息 */
	std::string info_template;
	/* hostname */
	std::string hostname_template;
	/* 操作系统 */
	std::string ostype_template;
	/* 设备类型 */
	std::string devicetype_template;
	/* cpe */
	std::string cpe_template;
	/* 正则表达式 */
	pcre* regex_compiled;
};

class ServiceProbe
{
public:
	ServiceProbe();
	~ServiceProbe();
	const std::string getName() { return probename; }
	bool isNullProbe() { return (probestringlen == 0); }
	void addMatch(cJSON *match, int lineno);
	void InitProbe(cJSON *match, int lineno);
	const struct MatchDetails *testMatch(const u8 *buf, int buflen);
	void setProbeDetails(cJSON *probe, int lineno);
	void setProbeString(char *ps, int stringlen);
	std::string getProbeString(int *stringlen) { *stringlen = probestringlen; return probestring; };
	void setPortVector(cJSON *ports);
	bool portIsProbable(unsigned int port);
	/* Protocols are IPPROTO_TCP and IPPROTO_UDP */
	u8 getProbeProtocol() {
		assert(probeprotocol == IPPROTO_TCP || probeprotocol == IPPROTO_UDP);
		return probeprotocol;
	}
	void setProbeProtocol(u8 protocol) { probeprotocol = protocol; }

public:
	/* probe名称 */
	std::string probename;
	/* 发送的probe内容 */
	std::string probestring;
	int probestringlen;
	/* 端口 */
	std::vector <unsigned int> probableports;
	/* 协议类型 */
	int probeprotocol;
	std::vector<ServiceProbeMatch *> matches;
};

class AllProbes {
public:
	AllProbes();
	~AllProbes();
	// Tries to find the probe in this AllProbes class which have the
	// given name and protocol.  It can return the NULL probe.
	ServiceProbe *getProbeByName(const char *name, int proto);
	std::vector<ServiceProbe *> probes; // All the probes except nullProbe
	ServiceProbe *nullProbe; // No probe text - just waiting for banner
	static AllProbes *service_scan_init(void);
protected:
	static AllProbes *global_AP;
};

#endif