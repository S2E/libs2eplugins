///
/// Copyright (C) 2017, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/S2E.h>

#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include <klee/util/ExprTemplates.h>

#include <cctype>
#include <sstream>

#include "GoogleCTFUnbreakable.h"

static const uint64_t SUCCESS_ADDRESS = 0x400724;
static const uint64_t FAILURE_ADDRESS = 0x400850;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(GoogleCTFUnbreakable,
                  "Solution for the unbreakable-enterprise-product-activation challenge from the Google CTF 2016", "",
                  "ProcessExecutionDetector");

void GoogleCTFUnbreakable::initialize() {
    // We need to use the ProcessExecutionDetector plugin to filter out all processes other than the "unbreakable"
    // process
    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();

    s2e()->getCorePlugin()->onSymbolicVariableCreation.connect(
        sigc::mem_fun(*this, &GoogleCTFUnbreakable::onSymbolicVariableCreation));
    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
        sigc::mem_fun(*this, &GoogleCTFUnbreakable::onTranslateInstruction));
}

void GoogleCTFUnbreakable::onSymbolicVariableCreation(S2EExecutionState *state, const std::string &name,
                                                      const std::vector<klee::ref<klee::Expr>> &expr,
                                                      const klee::MemoryObject *mo, const klee::Array *array) {
    // This check is not strictly required, because we only have one symbolic variable in the analysis.
    //
    // Program arguments made symbolic with the S2E_SYM_ARGS environment variable always have the name "argX", where
    // "X" is the argument index (starting with X = 1 for the first argument)
    if (name != "arg1") {
        return;
    }

    // We know that the product activation key starts with "CTF{". We encode this information as KLEE constraints
    state->constraints.addConstraint(E_EQ(expr[0], E_CONST('C', klee::Expr::Int8)));
    state->constraints.addConstraint(E_EQ(expr[1], E_CONST('T', klee::Expr::Int8)));
    state->constraints.addConstraint(E_EQ(expr[2], E_CONST('F', klee::Expr::Int8)));
    state->constraints.addConstraint(E_EQ(expr[3], E_CONST('{', klee::Expr::Int8)));

    // The following code has been removed because it has varying effects on S2E's performance. For example,
    // constraining that all other characters must be non-NULL slightly improves performance. However,
    // over-constraining the characters so that they must all be printable ASCII characters significantly effects
    // performance.
    //
    // The code is left here so that the user can experiement with constraining the product activation code in
    // different ways and how this can impact performance.
#if 0
    for (unsigned i = 4; i < expr.size(); ++i) {
#if 0
        state->constraints.addConstraint(E_NEQ(expr[i], E_CONST('\0', klee::Expr::Int8)));
#endif

        state->constraints.addConstraint(E_GE(expr[i], E_CONST(' ', klee::Expr::Int8)));
        state->constraints.addConstraint(E_LE(expr[i], E_CONST('~', klee::Expr::Int8)));
    }
#endif
}

void GoogleCTFUnbreakable::onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state,
                                                  TranslationBlock *tb, uint64_t pc) {
    if (!m_procDetector->isTracked(state)) {
        return;
    }

    if (pc == SUCCESS_ADDRESS) {
        signal->connect(sigc::mem_fun(*this, &GoogleCTFUnbreakable::onSuccess));
    } else if (pc == FAILURE_ADDRESS) {
        signal->connect(sigc::mem_fun(*this, &GoogleCTFUnbreakable::onFailure));
    }
}

void GoogleCTFUnbreakable::onSuccess(S2EExecutionState *state, uint64_t pc) {
    // `results` is a vector containing pairs of strings and a vector of bytes. The string corresponds to the symbolic
    // variable's name while the vector of bytes is the actual solution
    std::vector<std::pair<std::string, std::vector<unsigned char>>> results;

    // Invoke the constraint solver
    if (!s2e()->getExecutor()->getSymbolicSolution(*state, results)) {
        getWarningsStream(state) << "Unable to generate a solution for the product activation code\n";
        exit(1);
    }

    // Since we only have a single symbolic variable, we will only have a single result. We then iterate over the
    // bytes in this result to print the solution
    std::stringstream ss;
    for (auto c : results[0].second) {
        if (!std::isprint(c)) {
            break;
        }
        ss << (char) c;
    }

    getInfoStream(state) << "Product activation code = " << ss.str() << "\n";

    // No need to continue running S2E - terminate
    exit(0);
}

void GoogleCTFUnbreakable::onFailure(S2EExecutionState *state, uint64_t pc) {
    // There is no reason to continue execution any further. So kill the state
    s2e()->getExecutor()->terminateStateEarly(*state, "Invalid path");
}

} // namespace plugins
} // namespace s2e
