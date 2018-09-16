///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>

#include <klee/util/ExprTemplates.h>

#include "StaticFunctionModels.h"

using namespace klee;

namespace s2e {
namespace plugins {
namespace models {

S2E_DEFINE_PLUGIN(StaticFunctionModels, "Plugin that implements models for statically linked binaries", "", "MemUtils",
                  "ModuleExecutionDetector");

/*
 * Sample s2e-config.lua to use this plugin:
 *
 * pluginsConfig.StaticFunctionModels = {
 *   modules = {}
 * }
 *
 * g_function_models = {}
 *
 * g_function_models["TNETS_00002_patched"] = {}
 * g_function_models["TNETS_00002_patched"][0x8049b20] = {
 *   type="strlen",
 *   accepts_null_input = true,
 * }
 *
 * pluginsConfig.StaticFunctionModels.modules = g_function_models
*/
void StaticFunctionModels::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_memutils = s2e()->getPlugin<MemUtils>();

    m_handlers["strcpy"] = &StaticFunctionModels::handleStrcpy;
    m_handlers["strncpy"] = &StaticFunctionModels::handleStrncpy;
    m_handlers["strlen"] = &StaticFunctionModels::handleStrlen;
    m_handlers["strcmp"] = &StaticFunctionModels::handleStrcmp;
    m_handlers["strncmp"] = &StaticFunctionModels::handleStrncmp;
    m_handlers["strcat"] = &StaticFunctionModels::handleStrcat;
    m_handlers["strncat"] = &StaticFunctionModels::handleStrncat;

    m_handlers["memcpy"] = &StaticFunctionModels::handleMemcpy;
    m_handlers["memcmp"] = &StaticFunctionModels::handleMemcmp;

    m_handlers["crc16"] = &StaticFunctionModels::handleCrc16;
    m_handlers["crc32"] = &StaticFunctionModels::handleCrc32;

    getInfoStream() << "Model count: " << getFunctionModelCount() << "\n";

    m_detector->onModuleTranslateBlockEnd.connect(
        sigc::mem_fun(*this, &StaticFunctionModels::onModuleTranslateBlockEnd));
}

unsigned StaticFunctionModels::getFunctionModelCount() const {
    ConfigFile *cfg = s2e()->getConfig();

    return cfg->getInt(getConfigKey() + ".count");
}

bool StaticFunctionModels::getBool(S2EExecutionState *state, const std::string &property) {
    std::stringstream ss;
    const ModuleDescriptor *module = m_detector->getModule(state, state->regs()->getPc());
    assert(module);

    ss << getConfigKey() << ".modules[\"" << module->Name << "\"][" << hexval(state->regs()->getPc()) << "]."
       << property;

    return s2e()->getConfig()->getBool(ss.str());
}

void StaticFunctionModels::onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                     const ModuleDescriptor &module, TranslationBlock *tb,
                                                     uint64_t endPc, bool staticTarget, uint64_t targetPc) {
    // Only instrument direct calls
    if (!staticTarget || tb->se_tb_type != TB_CALL) {
        return;
    }

    // Check if we call a known string function
    uint64_t pc = module.ToNativeBase(targetPc);

    std::stringstream ss;
    ss << getConfigKey() << ".modules[\"" << module.Name << "\"]"
       << "[" << hexval(pc) << "]";

    ConfigFile *cfg = s2e()->getConfig();
    bool origSilent = cfg->isSilent();
    cfg->setSilent(true);

    bool ok;
    std::string type = cfg->getString(ss.str() + ".type", "", &ok);
    if (!ok) {
        return;
    }

    getDebugStream(state) << "Found function " << type << "\n";

    // Check handlers
    HandlerMap::const_iterator it = m_handlers.find(type);
    if (it != m_handlers.end()) {
        getDebugStream(state) << "Found handler for function " << type << "\n";
        signal->connect(sigc::bind(sigc::mem_fun(*this, &StaticFunctionModels::onCall), it->second));
    }

    cfg->setSilent(origSilent);
}

void StaticFunctionModels::onCall(S2EExecutionState *state, uint64_t pc, StaticFunctionModels::OpHandler handler) {
    state->undoCallAndJumpToSymbolic();

    bool handled = ((*this).*handler)(state);
    if (handled) {
        state->bypassFunction(0);
    } else {
        getDebugStream(state) << "Handling function at PC " << hexval(pc) << " failed, falling back to original code\n";
    }
}

bool StaticFunctionModels::handleStrcpy(S2EExecutionState *state) {
    // Read function arguments
    uint64_t dest;
    if (!readArgument(state, 0, dest)) {
        getDebugStream(state) << "Failed to read dest argument\n";
        return false;
    }

    uint64_t src;
    if (!readArgument(state, 1, src)) {
        getDebugStream(state) << "Failed to read src argument\n";
        return false;
    }

    // Assemble the string copy expression
    ref<Expr> retExpr;
    return strcpyHelper(state, dest, src, retExpr);
}

bool StaticFunctionModels::handleStrncpy(S2EExecutionState *state) {
    // Read function arguments
    uint64_t dest;
    if (!readArgument(state, 0, dest)) {
        getDebugStream(state) << "Failed to read dest argument\n";
        return false;
    }

    uint64_t src;
    if (!readArgument(state, 1, src)) {
        getDebugStream(state) << "Failed to read src argument\n";
        return false;
    }

    size_t n;
    if (!readArgument(state, 2, n)) {
        getDebugStream(state) << "Failed to read n argument\n";
        return false;
    }

    // Assemble the string copy expression
    ref<Expr> retExpr;
    return strncpyHelper(state, dest, src, n, retExpr);
}

bool StaticFunctionModels::handleStrlen(S2EExecutionState *state) {
    // Read function arguments
    uint64_t str;
    if (!readArgument(state, 0, str)) {
        getDebugStream(state) << "Failed to read str argument\n";
        return false;
    }

    // Assemble the string length expression
    ref<Expr> retExpr;
    if (strlenHelper(state, str, retExpr)) {
        state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);

        return true;
    } else {
        return false;
    }
}

bool StaticFunctionModels::handleStrcmp(S2EExecutionState *state) {
    // Read function arguments
    uint64_t str1;
    if (!readArgument(state, 0, str1)) {
        getDebugStream(state) << "Failed to read str1 argument\n";
        return false;
    }

    uint64_t str2;
    if (!readArgument(state, 1, str2)) {
        getDebugStream(state) << "Failed to read str2 argument\n";
        return false;
    }

    // Assemble the string compare expression
    ref<Expr> retExpr;
    if (strcmpHelper(state, str1, str2, retExpr)) {
        // Invert the result if required
        if (getBool(state, "inverted")) {
            getDebugStream(state) << "strcmp returns inverted result\n";
            retExpr = E_SUB(E_CONST(0, state->getPointerSize() * CHAR_BIT), retExpr);
        }

        state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);

        return true;
    } else {
        return false;
    }
}

bool StaticFunctionModels::handleStrncmp(S2EExecutionState *state) {
    // Read function arguments
    uint64_t str1;
    if (!readArgument(state, 0, str1)) {
        getDebugStream(state) << "Failed to read str1 argument\n";
        return false;
    }

    uint64_t str2;
    if (!readArgument(state, 1, str2)) {
        getDebugStream(state) << "Failed to read str2 argument\n";
        return false;
    }

    size_t n;
    if (!readArgument(state, 2, n)) {
        getDebugStream(state) << "Failed to read n argument\n";
        return false;
    }

    // Assemble the string compare expression
    ref<Expr> retExpr;
    if (strncmpHelper(state, str1, str2, n, retExpr)) {
        // Invert the result if required
        if (getBool(state, "inverted")) {
            getDebugStream(state) << "strncmp returns inverted result\n";
            retExpr = E_SUB(E_CONST(0, state->getPointerSize() * CHAR_BIT), retExpr);
        }

        state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);

        return true;
    } else {
        return false;
    }
}

bool StaticFunctionModels::handleStrcat(S2EExecutionState *state) {
    // Read function arguments
    uint64_t dest;
    if (!readArgument(state, 0, dest)) {
        getDebugStream(state) << "Failed to read dest argument\n";
        return false;
    }

    uint64_t src;
    if (!readArgument(state, 1, src)) {
        getDebugStream(state) << "Failed to read src argument\n";
        return false;
    }

    // Assemble the string concatenation expression
    ref<Expr> retExpr;
    return strcatHelper(state, dest, src, retExpr);
}

bool StaticFunctionModels::handleStrncat(S2EExecutionState *state) {
    // Read function arguments
    uint64_t dest;
    if (!readArgument(state, 0, dest)) {
        getDebugStream(state) << "Failed to read dest argument\n";
        return false;
    }

    uint64_t src;
    if (!readArgument(state, 1, src)) {
        getDebugStream(state) << "Failed to read src argument\n";
        return false;
    }

    size_t n;
    if (!readArgument(state, 2, n)) {
        getDebugStream(state) << "Failed to read n argument\n";
        return false;
    }

    // Assemble the string concatenation expression
    ref<Expr> retExpr;
    return strncatHelper(state, dest, src, n, retExpr);
}

bool StaticFunctionModels::handleMemcpy(S2EExecutionState *state) {
    // Read function arguments
    uint64_t dest;
    if (!readArgument(state, 0, dest)) {
        getDebugStream(state) << "Failed to read dest argument\n";
        return false;
    }

    uint64_t src;
    if (!readArgument(state, 1, src)) {
        getDebugStream(state) << "Failed to read src argument\n";
        return false;
    }

    size_t n;
    if (!readArgument(state, 2, n)) {
        getDebugStream(state) << "Failed to read n argument\n";
        return false;
    }

    // Assemble the memory copy expression
    ref<Expr> retExpr;
    return memcpyHelper(state, dest, src, n, retExpr);
}

bool StaticFunctionModels::handleMemcmp(S2EExecutionState *state) {
    // Read function arguments
    uint64_t s1;
    if (!readArgument(state, 0, s1)) {
        getDebugStream(state) << "Failed to read s1 argument\n";
        return false;
    }

    uint64_t s2;
    if (!readArgument(state, 1, s2)) {
        getDebugStream(state) << "Failed to read s2 argument\n";
        return false;
    }

    size_t n;
    if (!readArgument(state, 2, n)) {
        getDebugStream(state) << "Failed to read n argument\n";
        return false;
    }

    // Assemble the memory compare expression
    ref<Expr> retExpr;
    if (memcmpHelper(state, s1, s2, n, retExpr)) {
        state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);

        return true;
    } else {
        return false;
    }
}

bool StaticFunctionModels::handleCrc16(S2EExecutionState *state) {
    uint64_t initialCrc;
    if (!readArgument(state, 0, initialCrc)) {
        getWarningsStream(state) << "crc16: could not read initial crc\n";
        return false;
    }

    uint64_t dataAddr;
    if (!readArgument(state, 1, dataAddr)) {
        getWarningsStream(state) << "crc16: could not read data address\n";
        return false;
    }

    uint64_t len;
    if (!readArgument(state, 2, len)) {
        getWarningsStream(state) << "crc16: could not read len\n";
        return false;
    }

    std::vector<ref<Expr>> data;
    if (!m_memutils->read(state, data, dataAddr, len)) {
        getWarningsStream(state) << "crc16: could not read data\n";
        return false;
    }

    getDebugStream(state) << "Handling crc16(" << initialCrc << ", " << hexval(dataAddr) << ", " << len << ")\n";

    ref<Expr> crc = crc16(E_CONST(initialCrc, Expr::Int16), data);
    state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), crc);

    return true;
}

bool StaticFunctionModels::handleCrc32(S2EExecutionState *state) {
    uint64_t initialCrc;
    if (!readArgument(state, 0, initialCrc)) {
        getWarningsStream(state) << "crc32: could not read initial crc\n";
        return false;
    }

    uint64_t dataAddr;
    if (!readArgument(state, 1, dataAddr)) {
        getWarningsStream(state) << "crc32: could not read data address\n";
        return false;
    }

    uint64_t len;
    if (!readArgument(state, 2, len)) {
        getWarningsStream(state) << "crc32: could not read len\n";
        return false;
    }

    std::vector<ref<Expr>> data;
    if (!m_memutils->read(state, data, dataAddr, len)) {
        getWarningsStream(state) << "crc32: could not read data\n";
        return false;
    }

    getDebugStream(state) << "Handling crc32(" << initialCrc << ", " << hexval(dataAddr) << ", " << len << ")\n";

    ref<Expr> crc = crc32(E_CONST(initialCrc, Expr::Int32), data, getBool(state, "xor_result"));
    state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), crc);

    return true;
}

} // namespace models
} // namespace plugins
} // namespace s2e
