#include "url_parser.h"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace urlguardian {

namespace {

std::vector<std::string> split(const std::string& text, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream stream(text);
    std::string part;
    while (std::getline(stream, part, delimiter)) {
        if (!part.empty()) {
            parts.push_back(part);
        }
    }
    return parts;
}

std::string toLower(const std::string& text) {
    std::string result = text;
    std::transform(result.begin(), result.end(), result.begin(),
                    [](unsigned char c) { return std::tolower(c); });
    return result;
}

} // namespace anonimo

bool isIpv4Address(const std::string& host) {
    std::vector<std::string> groups = split(host, '.');
    if (groups.size() != 4) {
        return false;
    }
    for (const auto& group : groups) {
        if (group.empty() || group.size() > 3) {
            return false;
        }
        for (char c : group) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                return false;
            }
        }
        int value = std::stoi(group);
        if (value < 0 || value > 255) {
            return false;
        }
    }
    return true;
}

ParsedUrl parse(const std::string& rawUrl) {
    ParsedUrl result;
    result.original = rawUrl;

    std::string remaining = rawUrl;

    size_t schemePos = remaining.find("://");
    if (schemePos != std::string::npos) {
        result.scheme = toLower(remaining.substr(0, schemePos));
        remaining = remaining.substr(schemePos + 3);
    } else {
        result.scheme = "http";
    }

    std::string authority;
    std::string pathAndQuery;
    size_t slashPos = remaining.find('/');
    if (slashPos != std::string::npos) {
        authority = remaining.substr(0, slashPos);
        pathAndQuery = remaining.substr(slashPos);
    } else {
        authority = remaining;
        pathAndQuery = "";
    }

    size_t atPos = authority.find('@');
    if (atPos != std::string::npos) {
        result.hasUserInfo = true;
        authority = authority.substr(atPos + 1);
    }

    size_t portPos = authority.find(':');
    std::string host = (portPos != std::string::npos)
                            ? authority.substr(0, portPos)
                            : authority;
    host = toLower(host);
    result.host = host;

    size_t queryPos = pathAndQuery.find('?');
    if (queryPos != std::string::npos) {
        result.path = pathAndQuery.substr(0, queryPos);
        result.query = pathAndQuery.substr(queryPos + 1);
    } else {
        result.path = pathAndQuery;
        result.query = "";
    }

    result.hostIsIpAddress = isIpv4Address(host);

    if (!result.hostIsIpAddress && !host.empty()) {
        std::vector<std::string> labels = split(host, '.');

        if (labels.size() >= 2) {
            result.tld = labels.back();
            result.domain = labels[labels.size() - 2] + "." + labels.back();

            for (size_t i = 0; i + 2 < labels.size(); ++i) {
                result.subdomains.push_back(labels[i]);
            }
        } else if (labels.size() == 1) {
            result.domain = labels[0];
        }
    }

    return result;
}

} // namespace urlguardian
