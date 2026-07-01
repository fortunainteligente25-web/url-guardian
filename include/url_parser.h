#ifndef URL_PARSER_H
#define URL_PARSER_H

#include <string>
#include <vector>

namespace urlguardian {

struct ParsedUrl {
    std::string original;
    std::string scheme;
    std::string host;
    std::string domain;
    std::vector<std::string> subdomains;
    std::string tld;
    std::string path;
    std::string query;
    bool hasUserInfo = false;
    bool hostIsIpAddress = false;
};

ParsedUrl parse(const std::string& rawUrl);
bool isIpv4Address(const std::string& host);

} // namespace urlguardian

#endif // URL_PARSER_H
