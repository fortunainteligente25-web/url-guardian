#ifndef HEURISTICS_H
#define HEURISTICS_H

#include <string>
#include <vector>
#include "url_parser.h"

namespace urlguardian {

enum class Verdict {
    SAFE,
    SUSPICIOUS,
    MALICIOUS
};

struct RiskSignal {
    std::string description;
    int score;
};

struct AnalysisResult {
    ParsedUrl url;
    std::vector<RiskSignal> signals;
    int totalScore = 0;
    Verdict verdict = Verdict::SAFE;
};

AnalysisResult analyze(const std::string& rawUrl);
std::string verdictToString(Verdict verdict);

} // namespace urlguardian

#endif // HEURISTICS_H
