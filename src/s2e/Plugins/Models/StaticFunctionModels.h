///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_StaticFunctionModels_H
#define S2E_PLUGINS_StaticFunctionModels_H

#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>

#include <llvm/ADT/StringMap.h>

#include "BaseFunctionModels.h"

namespace s2e {

class S2E;
class S2EExecutionState;

namespace plugins {

class ModuleExecutionDetector;

namespace models {

class StaticFunctionModels : public BaseFunctionModels {
    S2E_PLUGIN

public:
    StaticFunctionModels(S2E *s2e) : BaseFunctionModels(s2e) {
    }

    void initialize();

    ///
    /// \brief Returns how many function models are available.
    ///
    unsigned getFunctionModelCount() const;

private:
    using OpHandler = bool (StaticFunctionModels::*)(S2EExecutionState *);
    using HandlerMap = llvm::StringMap<OpHandler>;

    ModuleExecutionDetector *m_detector;
    HandlerMap m_handlers;

    void onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                   TranslationBlock *tb, uint64_t endPc, bool staticTarget, uint64_t targetPc);

    bool getBool(S2EExecutionState *state, const std::string &property);

    //
    // String functions
    //

    bool handleStrcpy(S2EExecutionState *state);
    bool handleStrncpy(S2EExecutionState *state);
    bool handleStrlen(S2EExecutionState *state);
    bool handleStrcmp(S2EExecutionState *state);
    bool handleStrncmp(S2EExecutionState *state);
    bool handleStrcat(S2EExecutionState *state);
    bool handleStrncat(S2EExecutionState *state);

    //
    // Memory functions
    //

    bool handleMemcpy(S2EExecutionState *state);
    bool handleMemcmp(S2EExecutionState *state);

    //
    // CRC functions
    //

    bool handleCrc16(S2EExecutionState *state);
    bool handleCrc32(S2EExecutionState *state);

    void onCall(S2EExecutionState *state, uint64_t pc, OpHandler handler);
};

} // namespace models
} // namespace plugins
} // namespace s2e

#endif
