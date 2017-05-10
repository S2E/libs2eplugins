///
/// Copyright (C) 2011 - 2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <cpu/tb.h>

#include <s2e/CorePlugin.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "LibraryCallMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LibraryCallMonitor, "Monitors external library function calls", "", "ModuleMap", "OSMonitor",
                  "ProcessExecutionDetector");

void LibraryCallMonitor::initialize() {
    m_map = static_cast<ModuleMap *>(s2e()->getPlugin("ModuleMap"));
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_procDetector = static_cast<ProcessExecutionDetector *>(s2e()->getPlugin("ProcessExecutionDetector"));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &LibraryCallMonitor::onTranslateBlockEnd));
}

void LibraryCallMonitor::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc, bool isStatic, uint64_t staticTarget) {
    // Only interested in particular modules
    if (!m_procDetector->isTracked(state)) {
        return;
    }

    // Library calls are always indirect calls
    if (tb->se_tb_type == TB_CALL_IND) {
        signal->connect(sigc::mem_fun(*this, &LibraryCallMonitor::onIndirectCall));
    }
}

void LibraryCallMonitor::onIndirectCall(S2EExecutionState *state, uint64_t pc) {
    // Only interested in particular modules
    if (!m_procDetector->isTracked(state)) {
        return;
    }

    // Get the loaded modules for the current process
    uint64_t pid = m_monitor->getPid(state);
    ModuleDescriptorList mods = m_map->getModulesByPid(state, pid);

    uint64_t targetAddr = state->getPc();

    // Find the module that contains the call target
    for (auto const &mod : mods) {
        if (mod->Contains(targetAddr)) {
            vmi::Exports exps;
            if (!m_monitor->getExports(state, *mod, exps)) {
                getWarningsStream(state) << "unable to get exports for " << mod->Name << "\n";
                break;
            }

            // Find the export that matches the call target
            for (auto const &exp : exps) {
                if (targetAddr == exp.second) {
                    const ModuleDescriptor *currentMod = m_map->getModule(state, pc);
                    getInfoStream(state) << currentMod->Name << "@" << hexval(currentMod->ToNativeBase(pc))
                                         << " called function " << exp.first << "\n";

                    onLibraryCall.emit(state, *currentMod, targetAddr);
                    break;
                }
            }

            break;
        }
    }
}

} // namespace plugins
} // namespace s2e
