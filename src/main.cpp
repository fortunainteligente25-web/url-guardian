#include <iostream>
#include <iomanip>
#include "heuristics.h"

using namespace urlguardian;

void printResult(const AnalysisResult& result) {
    std::cout << "\n============================================\n";
    std::cout << " URL analizada : " << result.url.original << "\n";
    std::cout << " Dominio       : " << result.url.domain << "\n";
    std::cout << " Score riesgo  : " << result.totalScore << " / 100\n";
    std::cout << " Veredicto     : " << verdictToString(result.verdict) << "\n";
    std::cout << "============================================\n";

    if (result.signals.empty()) {
        std::cout << "No se detectaron senales de riesgo.\n";
    } else {
        std::cout << "Senales detectadas:\n";
        for (const auto& signal : result.signals) {
            std::cout << "  - [+" << std::setw(2) << signal.score << "] "
                       << signal.description << "\n";
        }
    }

    switch (result.verdict) {
        case Verdict::SAFE:
            std::cout << "\nNo se han encontrado indicios claros de riesgo.\n";
            break;
        case Verdict::SUSPICIOUS:
            std::cout << "\nEsta URL presenta senales sospechosas. "
                          "Revisa el dominio antes de continuar.\n";
            break;
        case Verdict::MALICIOUS:
            std::cout << "\nEsta URL presenta multiples senales de riesgo alto. "
                          "Se recomienda NO acceder.\n";
            break;
    }
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc >= 2) {
        std::string url = argv[1];
        AnalysisResult result = analyze(url);
        printResult(result);
        return 0;
    }

    std::cout << "URL Guardian - Detector heuristico de URLs maliciosas\n";
    std::cout << "Escribe una URL para analizarla (o 'salir' para terminar)\n";

    std::string input;
    while (true) {
        std::cout << "\n> ";
        if (!std::getline(std::cin, input)) {
            break;
        }
        if (input == "salir" || input == "exit") {
            break;
        }
        if (input.empty()) {
            continue;
        }

        AnalysisResult result = analyze(input);
        printResult(result);
    }

    std::cout << "Hasta luego.\n";
    return 0;
}
