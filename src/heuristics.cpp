#include "heuristics.h"
#include <algorithm>
#include <cctype>
#include <set>

namespace urlguardian {

namespace {

constexpr int SUSPICIOUS_THRESHOLD = 30;
constexpr int MALICIOUS_THRESHOLD  = 60;

const std::set<std::string> RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "work", "click", "zip", "review", "country"
};

const std::vector<std::string> SENSITIVE_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "banking", "bank", "wallet",
    "suspended", "unlock", "recover"
};

const std::vector<std::string> COMMONLY_IMPERSONATED_BRANDS = {
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "bankia", "santander", "bbva"
};

std::string toLower(const std::string& text) {
    std::string result = text;
    std::transform(result.begin(), result.end(), result.begin(),
                    [](unsigned char c) { return std::tolower(c); });
    return result;
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

void checkIpAsHost(const ParsedUrl& url, std::vector<RiskSignal>& signals) {
    if (url.hostIsIpAddress) {
        signals.push_back({
            "El host es una direccion IP en lugar de un dominio (" + url.host + ")",
            25
        });
    }
}

void checkUserInfoTrick(const ParsedUrl& url, std::vector<RiskSignal>& signals) {
    if (url.hasUserInfo) {
        signals.push_back({
            "La URL contiene '@', posible truco para ocultar el dominio real",
            30
        });
    }
}

void checkExcessiveSubdomains(const ParsedUrl& url, std::vector<RiskSignal>& signals) {
    if (url.subdomains.size() >= 3) {
        signals.push_back({
            "La URL tiene un numero inusual de subdominios (" +
                std::to_string(url.subdomains.size()) + ")",
            20
        });
    }
}

void checkUrlLength(const ParsedUrl& url, std::vector<RiskSignal>& signals) {
    const size_t length = url.original.size();
    if (length > 100) {
        signals.push_back({
            "La URL es inusualmente larga (" + std::to_string(length) + " caracteres)",
            10
        });
    }
}

void checkRiskyTld(const ParsedUrl& url, std::vector<RiskSignal>& signals) {
    if (RISKY_TLDS.count(toLower(url.tld)) > 0) {
        signals.push_back({
            "El dominio usa una extension (." + url.tld +
                ") frecuentemente asociada a spam o phishing",
            15
        });
    }
}

void checkSensitiveKeywords(const ParsedUrl& url, std::vector<RiskSignal>& signals) {
    const std::string haystack = toLower(url.host + url.path);
    int matches = 0;
    for (const auto& keyword : SENSITIVE_KEYWORDS) {
        if (contains(haystack, keyword)) {
            ++matches;
        }
    }
    if (matches > 0) {
        signals.push_back({
            "Se detectaron " + std::to_string(matches) +
                " palabra(s) clave sensibles (login, verify, secure...)",
            5 * matches
        });
    }
}

void checkBrandImpersonation(const ParsedUrl& url, std::vector<RiskSignal>& signals) {
    const std::string domainLower = toLower(url.domain);

    for (const auto& brand : COMMONLY_IMPERSONATED_BRANDS) {
        bool brandInDomain = contains(domainLower, brand);
        bool isOfficialDomain = (domainLower == brand + ".com") ||
                                 (domainLower == brand + ".es");
        if (brandInDomain && !isOfficialDomain) {
            signals.push_back({
                "El dominio contiene la marca '" + brand +
                    "' pero no coincide con su dominio oficial",
                35
            });
            break;
        }
    }
}

void checkExcessiveHyphens(const ParsedUrl& url, std::vector<RiskSignal>& signals) {
    int hyphenCount = static_cast<int>(
        std::count(url.domain.begin(), url.domain.end(), '-'));
    if (hyphenCount >= 2) {
        signals.push_back({
            "El dominio contiene multiples guiones (" +
                std::to_string(hyphenCount) + "), patron comun en phishing",
            15
        });
    }
}

} // namespace anonimo

std::string verdictToString(Verdict verdict) {
    switch (verdict) {
        case Verdict::SAFE:       return "SEGURA";
        case Verdict::SUSPICIOUS: return "SOSPECHOSA";
        case Verdict::MALICIOUS:  return "MALICIOSA";
    }
    return "DESCONOCIDA";
}

AnalysisResult analyze(const std::string& rawUrl) {
    AnalysisResult result;
    result.url = parse(rawUrl);

    checkIpAsHost(result.url, result.signals);
    checkUserInfoTrick(result.url, result.signals);
    checkExcessiveSubdomains(result.url, result.signals);
    checkUrlLength(result.url, result.signals);
    checkRiskyTld(result.url, result.signals);
    checkSensitiveKeywords(result.url, result.signals);
    checkBrandImpersonation(result.url, result.signals);
    checkExcessiveHyphens(result.url, result.signals);

    for (const auto& signal : result.signals) {
        result.totalScore += signal.score;
    }

    if (result.totalScore > 100) {
        result.totalScore = 100;
    }

    if (result.totalScore >= MALICIOUS_THRESHOLD) {
        result.verdict = Verdict::MALICIOUS;
    } else if (result.totalScore >= SUSPICIOUS_THRESHOLD) {
        result.verdict = Verdict::SUSPICIOUS;
    } else {
        result.verdict = Verdict::SAFE;
    }

    return result;
}

} // namespace urlguardian
