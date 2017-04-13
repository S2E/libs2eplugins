///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/Searchers/SeedSearcher.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <klee/Solver.h>
#include <klee/util/ExprTemplates.h>

#include <iostream>

#include "DecreeMonitor.h"

using namespace klee;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(DecreeMonitor, "DecreeMonitor S2E plugin", "OSMonitor", "BaseInstructions", "Vmi");

namespace decree {

/// The start address of the kernel
static const uint64_t KERNEL_START_ADDRESS = 0xC0000000;

// TODO Get real stack size from process memory map
static const unsigned STACK_SIZE = 16 * 1024 * 1024;

} // namespace decree

/// \brief We assume allocation of this amount of memory will never fail
#define SAFE_ALLOCATE_SIZE (16 * 1024 * 1024)

DecreeMonitor::DecreeMonitor(S2E *s2e)
    : BaseLinuxMonitor(s2e, decree::KERNEL_START_ADDRESS, decree::STACK_SIZE, S2E_DECREEMON_COMMAND_VERSION) {
}

void DecreeMonitor::initialize() {
    m_base = s2e()->getPlugin<BaseInstructions>();
    m_vmi = s2e()->getPlugin<Vmi>();

    // XXX: fix me. Very basic plugins like monitors probably
    // shouldn't call other plugins.
    m_seedSearcher = s2e()->getPlugin<seeds::SeedSearcher>();

    // XXX: fix this circular dependency.
    m_detector = s2e()->getPlugin<ProcessExecutionDetector>();

    ConfigFile *cfg = s2e()->getConfig();

    m_invokeOriginalSyscalls = cfg->getBool(getConfigKey() + ".invokeOriginalSyscalls", false);

    m_printOpcodeOffsets = cfg->getBool(getConfigKey() + ".printOpcodeOffsets", false);

    m_symbolicReadLimitCount = cfg->getInt(getConfigKey() + ".symbolicReadLimitCount", 16 * 1024 * 1024);
    m_maxReadLimitCount = cfg->getInt(getConfigKey() + ".maxReadLimitCount", 16 * 1024 * 1024);
    if (!(m_symbolicReadLimitCount <= m_maxReadLimitCount)) {
        getWarningsStream() << "symbolicReadLimitCount must be smaller than maxReadLimitCount\n";
        exit(-1);
    }

    m_terminateOnSegfault = cfg->getBool(getConfigKey() + ".terminateOnSegfault", true);
    m_terminateProcessGroupOnSegfault = cfg->getBool(getConfigKey() + ".terminateProcessGroupOnSegfault", false);

    m_concolicMode = cfg->getBool(getConfigKey() + ".concolicMode", false);

    m_logWrittenData = cfg->getBool(getConfigKey() + ".logWrittenData", true);

    m_handleSymbolicAllocateSize = cfg->getBool(getConfigKey() + ".handleSymbolicAllocateSize", false);
    m_handleSymbolicBufferSize = cfg->getBool(getConfigKey() + ".handleSymbolicBufferSize", false);

    m_feedConcreteData = cfg->getString(getConfigKey() + ".feedConcreteData", "");
    m_symbolicReadLimitCount += m_feedConcreteData.length();
    m_maxReadLimitCount += m_feedConcreteData.length();

    m_firstSegfault = true;
    m_timeToFirstSegfault = -1;
    time(&m_startTime);
}

class DecreeMonitorState : public BaseLinuxMonitorState {
public:
    /* How many bytes (symbolic or concrete) were read by each pid */
    std::map<uint64_t /* pid */, uint64_t> m_readBytesCount;

    /* Sum of all the values in m_readBytesCount */
    unsigned m_totalReadBytesCount;

    std::vector<uint8_t> m_concreteData;
    bool m_invokeOriginalSyscalls;
    bool m_concolicMode;

    std::unordered_map<uint64_t /* pid */, DecreeMonitor::MemoryMap> m_memory;

    virtual DecreeMonitorState *clone() const {
        DecreeMonitorState *ret = new DecreeMonitorState(*this);
        /**
         * Can't use the original pov on alternate paths, because it
         * is out of sync.
         */
        ret->m_invokeOriginalSyscalls = false;
        ret->m_concolicMode = false;
        return ret;
    }

    DecreeMonitorState(bool invokeOriginalSyscalls, bool concolicMode) {
        m_invokeOriginalSyscalls = invokeOriginalSyscalls;
        m_concolicMode = concolicMode;
        m_totalReadBytesCount = 0;
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        DecreeMonitor *plugin = static_cast<DecreeMonitor *>(p);
        return new DecreeMonitorState(plugin->m_invokeOriginalSyscalls, plugin->m_concolicMode);
    }

    virtual ~DecreeMonitorState() {
    }
};

/// \brief find memory pages with given access rights
///
/// \param map process memory map
/// \param mustBeWritable true if page must be writable
/// \param mustBeExecutable true if page must be executable
/// \param pages the pages that have been found
///
void DecreeMonitor::FindMemoryPages(const DecreeMonitor::MemoryMap &map, bool mustBeWritable, bool mustBeExecutable,
                                    std::unordered_set<uint64_t> &pages) {
    foreach2 (it, map.begin(), map.end()) {
        assert((it->flags & S2E_DECREEMON_VM_READ) && "Memory area has no read access");
        assert(it->start % TARGET_PAGE_SIZE == 0 && "Memory area is not aligned to page boundary");
        assert(it->end % TARGET_PAGE_SIZE == 0 && "Memory area is not aligned to page boundary");

        if (mustBeWritable && !(it->flags & S2E_DECREEMON_VM_WRITE)) {
            continue;
        }
        if (mustBeExecutable && !(it->flags & S2E_DECREEMON_VM_EXEC)) {
            continue;
        }

        for (uint64_t addr = it->start; addr < it->end; addr += TARGET_PAGE_SIZE) {
            pages.insert(addr);
        }
    }
}

const DecreeMonitor::MemoryMap &DecreeMonitor::getMemoryMap(S2EExecutionState *state, uint64_t pid) {
    DECLARE_PLUGINSTATE(DecreeMonitorState, state);
    return plgState->m_memory[pid];
}

unsigned DecreeMonitor::getSymbolicReadsCount(S2EExecutionState *state) const {
    DECLARE_PLUGINSTATE_CONST(DecreeMonitorState, state);
    return plgState->m_totalReadBytesCount;
}

void DecreeMonitor::handleProcessLoad(S2EExecutionState *state, const S2E_DECREEMON_COMMAND_PROCESS_LOAD &p) {
    static bool loaded = false;

    if (!loaded) {
        onMonitorLoad.emit(state);
        loaded = true;
    }

    std::string processPath(p.process_path, strnlen(p.process_path, sizeof(p.process_path)));

    getWarningsStream(state) << "ProcessLoad: " << processPath << " entry_point: " << hexval(p.entry_point)
                             << " pid: " << hexval(p.process_id) << " start_code: " << hexval(p.start_code)
                             << " end_code: " << hexval(p.end_code) << " start_data: " << hexval(p.start_data)
                             << " end_data: " << hexval(p.end_data) << " start_stack: " << hexval(p.start_stack)
                             << "\n";

    llvm::StringRef file(processPath);

    onProcessLoad.emit(state, state->getPageDir(), p.process_id, llvm::sys::path::stem(file));

    ModuleDescriptor mod;
    mod.Name = llvm::sys::path::stem(file);
    mod.Path = file.str();
    mod.AddressSpace = state->getPageDir();
    mod.Pid = p.process_id;
    mod.LoadBase = p.start_code;
    mod.NativeBase = p.start_code;
    mod.Size = p.end_data - p.start_code;
    mod.EntryPoint = p.entry_point;
    mod.DataBase = p.start_data;
    mod.DataSize = p.end_data - p.start_data;
    mod.StackTop = p.start_stack;

    getDebugStream(state) << mod << "\n";

    onModuleLoad.emit(state, mod);

    DECLARE_PLUGINSTATE(DecreeMonitorState, state);
    plgState->saveModule(mod);
}

klee::ref<klee::Expr> DecreeMonitor::readMemory8(S2EExecutionState *state, uint64_t pid, uint64_t addr) {
    klee::ref<klee::Expr> expr = state->readMemory8(addr);
    if (!expr.isNull()) {
        return expr;
    }

    /* Try to read data from executable image */

    DECLARE_PLUGINSTATE(DecreeMonitorState, state);
    const ModuleDescriptor *mod = plgState->getModule(pid);
    if (!mod) {
        getDebugStream(state) << "No module for pid " << pid << "\n";
        return klee::ref<klee::Expr>(NULL);
    }

    uint8_t byte;
    if (!m_vmi->readModuleData(*mod, addr, byte)) {
        getDebugStream(state) << "Failed to read memory at address " << hexval(addr) << "\n";
        return klee::ref<klee::Expr>(NULL);
    }

    return klee::ConstantExpr::create(byte, klee::Expr::Int8);
}

uint64_t DecreeMonitor::getPid(S2EExecutionState *state, uint64_t pc) {
    target_ulong pid;
    target_ulong taskStructPtr = getTaskStructPtr(state);
    unsigned pidAddress = taskStructPtr + 320; // Offsets can be found with: pahole vmlinux -C task_struct

    if (!state->mem()->readMemoryConcrete(pidAddress, &pid, sizeof(pid))) {
        return -1;
    } else {
        return pid;
    }
}

uint64_t DecreeMonitor::getPid(S2EExecutionState *state) {
    return getPid(state, state->getPc());
}

uint64_t DecreeMonitor::getTid(S2EExecutionState *state) {
    return getPid(state);
}

void DecreeMonitor::getPreFeedData(S2EExecutionState *state, uint64_t pid, uint64_t count, std::vector<uint8_t> &data) {
    // TODO: fix POV generation - it does not use these concrete values

    DECLARE_PLUGINSTATE(DecreeMonitorState, state);

    s2e_assert(state, plgState->m_readBytesCount[pid] <= UINT64_MAX - count, "Read count overflow");
    s2e_assert(state, plgState->m_readBytesCount[pid] + count <= m_feedConcreteData.length(), "Invalid count");

    std::vector<uint8_t> buffer;
    for (unsigned i = 0; i < count; ++i) {
        uint8_t value = m_feedConcreteData[plgState->m_readBytesCount[pid] + i];
        data.push_back(value);
    }
}

void DecreeMonitor::getRandomData(S2EExecutionState *state, uint64_t count, std::vector<uint8_t> &data) {
    for (unsigned i = 0; i < count; ++i) {
        uint8_t value = rand();
        data.push_back(value);
    }
}

ref<Expr> DecreeMonitor::makeSymbolicRead(S2EExecutionState *state, uint64_t pid, uint64_t fd, uint64_t buf,
                                          uint64_t count, ref<Expr> countExpr) {
    DECLARE_PLUGINSTATE(DecreeMonitorState, state);

    if (plgState->m_readBytesCount[pid] < m_feedConcreteData.length()) {
        uint64_t feedCount = std::min(count, m_feedConcreteData.length() - plgState->m_readBytesCount[pid]);

        std::vector<uint8_t> data;
        getPreFeedData(state, pid, feedCount, data);

        bool ok = state->mem()->writeMemoryConcrete(buf, &data[0], feedCount);
        s2e_assert(state, ok, "Failed to write memory");

        plgState->m_readBytesCount[pid] += feedCount;
        plgState->m_totalReadBytesCount += feedCount;
        onConcreteRead.emit(state, pid, fd, data);
        return E_CONST(feedCount, Expr::Int32);
    }

    if (plgState->m_readBytesCount[pid] < m_symbolicReadLimitCount) {
        uint64_t feedCount = std::min(count, m_symbolicReadLimitCount - plgState->m_readBytesCount[pid]);
        ref<Expr> feedCountExpr = E_MIN(
            countExpr, E_CONST(m_symbolicReadLimitCount - plgState->m_readBytesCount[pid], countExpr->getWidth()));

        std::vector<std::pair<std::vector<klee::ref<klee::Expr>>, std::string>> data;
        for (unsigned i = 0; i < feedCount; i++) {
            std::vector<ref<Expr>> varData;
            std::string varName;
            m_base->makeSymbolic(state, buf + i, 1, "receive", true, &varData, &varName);
            data.push_back(std::make_pair(varData, varName));
        }

        plgState->m_readBytesCount[pid] += feedCount;
        plgState->m_totalReadBytesCount += feedCount;
        onSymbolicRead.emit(state, pid, fd, feedCount, data, feedCountExpr);
        return feedCountExpr;
    }

    if (plgState->m_readBytesCount[pid] < m_maxReadLimitCount) {
        /**
         * Note: using random data may lead to non-replayable POVs (mostly cookies)
         * This is meant to prevent path explosion in the simplest checker configuration.
         */

        static bool printed_warning = false;
        if (!printed_warning) {
            printed_warning = true;
            getDebugStream(state) << "Symbolic read threshold exceeded, using random data\n";
        }

        uint64_t feedCount = std::min(count, m_maxReadLimitCount - plgState->m_readBytesCount[pid]);

        std::vector<uint8_t> data;
        getRandomData(state, feedCount, data);

        bool ok = state->mem()->writeMemoryConcrete(buf, &data[0], feedCount);
        s2e_assert(state, ok, "Failed to write memory");

        plgState->m_readBytesCount[pid] += feedCount;
        plgState->m_totalReadBytesCount += feedCount;
        onConcreteRead.emit(state, pid, fd, data);
        return E_CONST(feedCount, Expr::Int32);
    }

    g_s2e->getExecutor()->terminateStateEarly(*state, "read data limit exceeded");
    return E_CONST(0, Expr::Int32);
}

void DecreeMonitor::handleReadData(S2EExecutionState *state, uint64_t pid, const S2E_DECREEMON_COMMAND_READ_DATA &d) {
    if (!isReadFd(d.fd)) {
        return;
    }

    bool isSeedState = m_seedSearcher ? m_seedSearcher->isSeedState(state) : false;

    ref<Expr> countExpr;
    if (m_handleSymbolicBufferSize && !isSeedState) {
        countExpr = state->mem()->readMemory(d.size_expr_addr, state->getPointerWidth());
        s2e_assert(state, !countExpr.isNull(), "Failed to read memory");
    } else {
        countExpr = E_CONST(d.buffer_size, Expr::Int32);
    }

    ref<Expr> bytesSentExpr = makeSymbolicRead(state, pid, d.fd, d.buffer, d.buffer_size, countExpr);

    if (isa<ConstantExpr>(bytesSentExpr)) {
        bool ok = state->writePointer(d.result_addr, dyn_cast<ConstantExpr>(bytesSentExpr)->getZExtValue());
        s2e_assert(state, ok, "Failed to write memory");
    } else {
        bool ok = state->mem()->writeMemory(d.result_addr, bytesSentExpr);
        s2e_assert(state, ok, "Failed to write memory");
    }

    DECLARE_PLUGINSTATE(DecreeMonitorState, state);
    getDebugStream(state) << "handleReadData: readCount=" << plgState->m_readBytesCount[pid]
                          << " for module=" << plgState->getModule(pid)->Name << "\n";
}

void DecreeMonitor::handleReadDataPost(S2EExecutionState *state, uint64_t pid,
                                       const S2E_DECREEMON_COMMAND_READ_DATA_POST &d) {
    if (!isReadFd(d.fd)) {
        return;
    }

    DECLARE_PLUGINSTATE(DecreeMonitorState, state);

    if (plgState->m_concolicMode) {
        std::vector<std::pair<std::vector<klee::ref<klee::Expr>>, std::string>> data;

        for (unsigned i = 0; i < d.buffer_size; i++) {
            std::vector<ref<Expr>> varData;
            std::string varName;

            m_base->makeSymbolic(state, d.buffer + i, 1, "receive", true, &varData, &varName);
            data.push_back(std::make_pair(varData, varName));
        }

        plgState->m_readBytesCount[pid] += d.buffer_size;
        plgState->m_totalReadBytesCount += d.buffer_size;
        onSymbolicRead.emit(state, pid, d.fd, d.buffer_size, data, ConstantExpr::create(d.buffer_size, Expr::Int32));

        getDebugStream(state) << "handleReadData: readCount=" << plgState->m_readBytesCount[pid]
                              << " for module=" << plgState->getModule(pid)->Name << "\n";
    }
}

void DecreeMonitor::handleWriteData(S2EExecutionState *state, uint64_t pid, const S2E_DECREEMON_COMMAND_WRITE_DATA &d) {
    if (!isWriteFd(d.fd)) {
        return;
    }

    uint64_t actualCount; // how many bytes were written to output by kernel
    bool ok = state->readPointer(d.buffer_size_addr, actualCount);
    s2e_assert(state, ok, "Failed to read memory");

    ref<Expr> countExpr = state->mem()->readMemory(d.size_expr_addr, state->getPointerWidth());
    s2e_assert(state, !countExpr.isNull(), "Failed to read memory");
    countExpr = E_MIN(countExpr, E_CONST(actualCount, state->getPointerWidth()));

    std::stringstream ss;

    std::vector<klee::ref<klee::Expr>> vec;
    for (unsigned i = 0; i < actualCount; ++i) {
        klee::ref<klee::Expr> e = readMemory8(state, pid, d.buffer + i);
        s2e_assert(state, !e.isNull(), "Failed to read memory byte of pid " << hexval(pid) << " at "
                                                                            << hexval(d.buffer + i));

        vec.push_back(e);

        if (m_logWrittenData) {
            if (isa<klee::ConstantExpr>(e)) {
                klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(e);
                ss << charval(ce->getZExtValue());
            } else {
                ss << e << " ";
            }
        }
    }

    if (m_logWrittenData) {
        getDebugStream(state) << "handleWriteData pid=" << hexval(pid) << " fd=" << d.fd << ": " << ss.str() << "\n";
    }

    bool isSeedState = m_seedSearcher ? m_seedSearcher->isSeedState(state) : false;
    if (m_handleSymbolicBufferSize && !isSeedState && !isa<ConstantExpr>(countExpr)) {
        bool ok = state->mem()->writeMemory(d.buffer_size_addr, countExpr);
        s2e_assert(state, ok, "Failed to write memory");
    }

    onWrite.emit(state, pid, d.fd, vec, countExpr);
}

void DecreeMonitor::handleFdWait(S2EExecutionState *state, S2E_DECREEMON_COMMAND &d, uintptr_t addr) {
    DECLARE_PLUGINSTATE(DecreeMonitorState, state);

    d.FDWait.invoke_orig = 0;
    if (plgState->m_invokeOriginalSyscalls) {
        d.FDWait.invoke_orig = 1;
    }

    if (d.FDWait.has_timeout) {
        using namespace klee;
        // Switch to symbolic mode
        state->jumpToSymbolicCpp();

        getDebugStream(state) << "fdwait timeout: " << d.FDWait.tv_sec << " " << d.FDWait.tv_nsec << "\n";

        // Create a symbolic timeout variable
        uint8_t val = 0;
        ref<Expr> timeout = state->createConcolicValue("timeout", val);

        // Build expression: if timeout == 0 then 0 else nfds
        ref<Expr> result = E_ITE(E_EQ(timeout, E_CONST(0, Expr::Int8)), //
                                 E_CONST(0, Expr::Int64), E_CONST(d.FDWait.nfds, Expr::Int64));

        // Need to write it back, the kernel reads 'invoke_orig'
        bool ok = state->mem()->writeMemoryConcrete(addr, &d, sizeof(d));
        s2e_assert(state, ok, "Failed to write memory");

        uintptr_t resultAddress = addr + offsetof(S2E_DECREEMON_COMMAND, FDWait.result);
        ok = state->mem()->writeMemory(resultAddress, result);
        s2e_assert(state, ok, "Failed to write memory");

        /*state->regs()->write<target_ulong>(CPU_OFFSET(eip), state->getPc() + 10);

        Executor::StatePair sp = s2e()->getExecutor()->fork(*state, condition, false);
        s2e()->getExecutor()->notifyFork(*state, condition, sp);

        throw CpuExitException();*/

    } else {
        d.FDWait.result = d.FDWait.nfds;
        bool ok = state->mem()->writeMemoryConcrete(addr, &d, sizeof(d));
        s2e_assert(state, ok, "Failed to write memory");
    }
}

void DecreeMonitor::handleRandom(S2EExecutionState *state, uint64_t pid, const S2E_DECREEMON_COMMAND_RANDOM &d) {
    // Always make this concolic, POV generator needs as many real concrete
    // values as possible.
    std::vector<klee::ref<klee::Expr>> data;

    // It is important to create one variable for each random byte.
    // The POVGenerator will assume one byte var == one byte nonce.
    for (uint64_t i = 0; i < d.buffer_size; ++i) {
        std::vector<klee::ref<klee::Expr>> sd;
        m_base->makeSymbolic(state, d.buffer + i, 1, "random", true, &sd);
        s2e_assert(NULL, sd.size() == 1, "makesymbolic returned wrong number of bytes");
        data.push_back(sd[0]);
    }

    onRandom.emit(state, pid, data);
}

void DecreeMonitor::handleGetCfgBool(S2EExecutionState *state, uint64_t pid, S2E_DECREEMON_COMMAND_GET_CFG_BOOL &d) {
    std::string key;
    bool ok = state->mem()->readString(d.key_addr, key, 256);
    s2e_assert(state, ok, "Failed to read memory");

    bool value;
    if (key == "invokeOriginalSyscalls") {
        DECLARE_PLUGINSTATE(DecreeMonitorState, state);

        // We always want to invoke original syscalls when not in cb process
        // (e.g., when in seed process, which are also decree binaries).
        // XXX: this induces  a circular dependency between DecreeMonitor and
        // ProcessExecutionDetector. Better design would be to have a signal
        // to ask other plugins whether this process should be instrumented or not.
        if (m_detector && !m_detector->isTracked(state, pid)) {
            value = true;
        } else {
            value = plgState->m_invokeOriginalSyscalls;
        }
    } else {
        s2e_assert(state, false, "Unknown config key name: " << key);
    }

    d.value = value;
}

uint64_t DecreeMonitor::getMaxValue(S2EExecutionState *state, ref<Expr> value) {
    std::pair<ref<Expr>, ref<Expr>> range;
    Query query(state->constraints, value);

    range = s2e()->getExecutor()->getSolver(*state)->getRange(query);

    return dyn_cast<ConstantExpr>(range.second)->getZExtValue();
}

void DecreeMonitor::handleSymbolicSize(S2EExecutionState *state, uint64_t pid, uint64_t safeLimit,
                                       klee::ref<klee::Expr> size, uint64_t sizeAddr) {
    if (state->isRunningConcrete()) {
        getDebugStream(state) << "Switching to symbolic mode\n";
        state->jumpToSymbolicCpp();
        assert(false && "Unreachable code");
    }

    // Override symbolic size variable with its maximum possible concrete value.
    // This prevents forking in kernel memory functions, still allowing binary
    // to fork on symbolic size.
    //
    // Additionally, fork a state where symbolic size has a reasonable upper bound.
    // This is to handle cases where maximum possible concrete value is too big.

    ref<Expr> sizeIsSafe = E_LE(size, E_CONST(safeLimit, state->getPointerWidth()));

    bool isSeedState = m_seedSearcher ? m_seedSearcher->isSeedState(state) : false;
    s2e_assert(state, !isSeedState, "Concolics will be recomputed because of keepConditionTrueInCurrentState=true");

    Executor::StatePair sp = s2e()->getExecutor()->forkCondition(state, sizeIsSafe, true);

    if (sp.first) {
        S2EExecutionState *s = dynamic_cast<S2EExecutionState *>(sp.first);
        s2e_assert(s, s->isActive(), "S2EExecutionState::writePointer requires state to be active");

        uint64_t max = getMaxValue(s, size);
        s2e_assert(s, max <= safeLimit, "Solver must be wrong about max size value " << hexval(max));

        bool ok = s->writePointer(sizeAddr, max);
        s2e_assert(s, ok, "Failed to write memory");

        getDebugStream(s) << "Using size " << hexval(max) << "\n";
    }

    if (sp.second) {
        S2EExecutionState *s = dynamic_cast<S2EExecutionState *>(sp.second);

        getDebugStream(s) << "Size may be too big, leaving it symbolic\n";
    }
}

void DecreeMonitor::handleSymbolicAllocateSize(S2EExecutionState *state, uint64_t pid,
                                               const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_SIZE &d) {
    ref<Expr> size = state->readMemory(d.size_addr, state->getPointerWidth());
    s2e_assert(state, !size.isNull(), "Failed to read memory");

    if (isa<ConstantExpr>(size)) {
        return;
    }

    getDebugStream(state) << "Symbolic allocate size in pid=" << hexval(pid) << "\n";

    if (!m_handleSymbolicAllocateSize) {
        return;
    }

    bool isSeedState = m_seedSearcher ? m_seedSearcher->isSeedState(state) : false;
    if (isSeedState) {
        return;
    }

    handleSymbolicSize(state, pid, SAFE_ALLOCATE_SIZE, size, d.size_addr);
}

/// \brief Find how many contiguous bytes we have in mapped memory
///
/// \param startAddr start from this address
/// \param pages set of mapped memory pages
/// \return size of memory region starting at \p startAddr and ending at first page not in the \p pages set
///
static uint64_t distanceToUnmappedPage(uint64_t startAddr, const std::unordered_set<uint64_t> &pages) {
    std::set<uint64_t> sortedPages(pages.begin(), pages.end());

    auto it = sortedPages.find(startAddr & TARGET_PAGE_MASK);
    if (it == sortedPages.end()) {
        return 0;
    }

    while (true) {
        auto nextIt = std::next(it);

        if (nextIt == sortedPages.end()) { // next page is not mapped
            break;
        }

        if (*nextIt != *it + TARGET_PAGE_SIZE) { // next page is not adjacent to *it
            break;
        }

        it = nextIt;
    }

    uint64_t endAddr = *it + TARGET_PAGE_SIZE;

    return endAddr - startAddr;
}

void DecreeMonitor::handleSymbolicBuffer(S2EExecutionState *state, uint64_t pid, SymbolicBufferType type,
                                         uint64_t ptrAddr, uint64_t sizeAddr) {
    ref<Expr> ptr = state->readMemory(ptrAddr, state->getPointerWidth());
    s2e_assert(state, !ptr.isNull(), "Failed to read memory");

    ref<Expr> size = state->readMemory(sizeAddr, state->getPointerWidth());
    s2e_assert(state, !size.isNull(), "Failed to read memory");

    bool isSymPtr = !isa<ConstantExpr>(ptr);
    bool isSymSize = !isa<ConstantExpr>(size);

    if (isSymPtr) {
        getDebugStream(state) << "Symbolic " << type << " buffer pointer in pid=" << hexval(pid) << "\n";
        onSymbolicBuffer.emit(state, pid, type, ptr, size);
    } else if (isSymSize) {
        getDebugStream(state) << "Symbolic " << type << " buffer size in pid=" << hexval(pid) << "\n";

        if (!m_handleSymbolicBufferSize) {
            return;
        }

        bool isSeedState = m_seedSearcher ? m_seedSearcher->isSeedState(state) : false;
        if (isSeedState) {
            return;
        }

        std::unordered_set<uint64_t> pages;
        FindMemoryPages(getMemoryMap(state), bufferMustBeWritable(type), false, pages);

        uint64_t ptrVal = dyn_cast<ConstantExpr>(ptr)->getZExtValue();
        uint64_t safeSize = distanceToUnmappedPage(ptrVal, pages);
        if (!safeSize) {
            getDebugStream(state) << "no memory in buffer at " << hexval(ptrVal) << "\n";
            return;
        }

        handleSymbolicSize(state, pid, safeSize, size, sizeAddr);
    }
}

void DecreeMonitor::handleSymbolicReceiveBuffer(S2EExecutionState *state, uint64_t pid,
                                                const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d) {
    handleSymbolicBuffer(state, pid, SYMBUFF_RECEIVE, d.ptr_addr, d.size_addr);
}

void DecreeMonitor::handleSymbolicTransmitBuffer(S2EExecutionState *state, uint64_t pid,
                                                 const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d) {
    handleSymbolicBuffer(state, pid, SYMBUFF_TRANSMIT, d.ptr_addr, d.size_addr);
}

void DecreeMonitor::handleSymbolicRandomBuffer(S2EExecutionState *state, uint64_t pid,
                                               const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d) {
    handleSymbolicBuffer(state, pid, SYMBUFF_RANDOM, d.ptr_addr, d.size_addr);
}

void DecreeMonitor::handleCopyToUser(S2EExecutionState *state, uint64_t pid,
                                     const S2E_DECREEMON_COMMAND_COPY_TO_USER &d) {
    if (!d.done) {
        return;
    }

    if (d.ret != 0) {
        getDebugStream(state) << "copy_to_user returned " << d.ret << "\n";
        return;
    }

    for (unsigned i = 0; i < d.count; ++i) {
        ref<Expr> value = state->mem()->readMemory(d.user_addr + i, Expr::Int8);
        if (value.isNull()) {
            getDebugStream(state) << "could not read address " << hexval(d.user_addr + i) << "\n";
            continue;
        }

        if (isa<ConstantExpr>(value)) {
            g_s2e->getCorePlugin()->onConcreteDataMemoryAccess.emit(state, d.user_addr + i,
                                                                    cast<klee::ConstantExpr>(value)->getZExtValue(), 1,
                                                                    MEM_TRACE_FLAG_WRITE | MEM_TRACE_FLAG_PLUGIN);
        } else {
            g_s2e->getCorePlugin()->onAfterSymbolicDataMemoryAccess.emit(
                state, ConstantExpr::create(d.user_addr + i, Expr::Int64), ConstantExpr::create(-1, Expr::Int64), value,
                MEM_TRACE_FLAG_WRITE | MEM_TRACE_FLAG_PLUGIN);
        }
    }
}

/// \brief Handle UPDATE_MEMORY_MAP command
///
/// Parses command arguments and emits onUpdateMemoryMap event.
///
/// \param state current state
/// \param pid PID of related process
/// \param d command data
void DecreeMonitor::handleUpdateMemoryMap(S2EExecutionState *state, uint64_t pid,
                                          const S2E_DECREEMON_COMMAND_UPDATE_MEMORY_MAP &d) {
    getDebugStream(state) << "New memory map for pid=" << hexval(pid) << "\n";

    DECLARE_PLUGINSTATE(DecreeMonitorState, state);

    if (!d.count) {
        plgState->m_memory[pid] = MemoryMap();
        onUpdateMemoryMap.emit(state, pid, plgState->m_memory[pid]);
        return;
    }

    S2E_DECREEMON_VMA buf[d.count];
    bool ok = state->mem()->readMemoryConcrete(d.buffer, buf, sizeof(buf));
    s2e_assert(state, ok, "Failed to read memory");

    for (unsigned i = 0; i < d.count; i++) {
        getDebugStream(state) << "  " << buf[i] << "\n";
    }

    plgState->m_memory[pid] = MemoryMap(buf, buf + d.count);
    onUpdateMemoryMap.emit(state, pid, plgState->m_memory[pid]);
}

///
/// \brief Read and writes CB parameters
///
/// This handler is called by the CB loader right after it parsed CB parameters.
/// It is possible to modify passed parameters.
///
/// \param state current state
/// \param pid PID of related process
/// \param d command data
///
void DecreeMonitor::handleSetParams(S2EExecutionState *state, uint64_t pid, S2E_DECREEMON_COMMAND_SET_CB_PARAMS &d) {
    auto &ss = getDebugStream(state);
    ss << "CB parameters: "
       << " cgc_max_receive: " << d.cgc_max_receive << " cgc_max_transmit: " << d.cgc_max_transmit
       << " skip_rng_count: " << d.skip_rng_count << " cgc_seed_ptr: " << hexval(d.cgc_seed_ptr)
       << " cgc_seed_len: " << d.cgc_seed_len;

    // This part prints the input seed.
    if (d.cgc_seed_ptr) {
        // Truncate the seed if it's too long.
        // This would normally never happen with CGC binaries whose seeds are 48 byte long,
        // but it is still good practice to check external inputs for sanity.
        unsigned len = d.cgc_seed_len;
        if (len > sizeof(d.cgc_seed)) {
            len = sizeof(d.cgc_seed);
        }
        uint8_t buffer[len];
        memset(buffer, 0, len);

        if (!state->mem()->readMemoryConcrete(d.cgc_seed_ptr, buffer, len)) {
            ss << "\n";
            getWarningsStream(state) << "Could not read seed\n";
        } else {
            ss << " seed: ";
            for (unsigned i = 0; i < len; ++i) {
                ss << hexval(buffer[i]) << " ";
            }
            ss << "\n";
        }
    } else {
        ss << "\n";
    }

    // Set output seed
    // TODO: Make this configurable. For now set it to all zeros.
    // CGC loader uses 48 byte seeds.
    const char newSeed[S2E_DECREEMON_DECREE_SEED_SIZE] = {0};

    // Can use this to double check the seed correctness.
    // The cgc loader will print the first skip_rng_count random values.
    // Don't use this in production.
    // d.skip_rng_count = 16;

    d.cgc_seed_len = sizeof(newSeed);
    memcpy(d.cgc_seed, newSeed, d.cgc_seed_len);
}

void DecreeMonitor::printOpcodeOffsets(S2EExecutionState *state) {
    getDebugStream(state) << "S2E_DECREEMON_COMMAND offsets:\n";

#define PRINTOFF(field)                                                                                          \
    do {                                                                                                         \
        off_t off = offsetof(S2E_DECREEMON_COMMAND, field);                                                      \
        size_t sz = sizeof(S2E_DECREEMON_COMMAND::field);                                                        \
        getDebugStream(state) << "  " << hexval(off, 2) << ".." << hexval(off + sz, 2) << " " << #field << "\n"; \
    } while (0)

    PRINTOFF(Command);
    PRINTOFF(currentPid);

    PRINTOFF(ProcessLoad.process_id);
    PRINTOFF(ProcessLoad.entry_point);
    PRINTOFF(ProcessLoad.cgc_header);
    PRINTOFF(ProcessLoad.start_code);
    PRINTOFF(ProcessLoad.end_code);
    PRINTOFF(ProcessLoad.start_data);
    PRINTOFF(ProcessLoad.end_data);
    PRINTOFF(ProcessLoad.start_stack);
    PRINTOFF(ProcessLoad.process_path);

    PRINTOFF(Data.fd);
    PRINTOFF(Data.buffer);
    PRINTOFF(Data.buffer_size);
    PRINTOFF(Data.size_expr_addr);
    PRINTOFF(Data.result_addr);

    PRINTOFF(DataPost.fd);
    PRINTOFF(DataPost.buffer);
    PRINTOFF(DataPost.buffer_size);

    PRINTOFF(WriteData.fd);
    PRINTOFF(WriteData.buffer);
    PRINTOFF(WriteData.buffer_size_addr);
    PRINTOFF(WriteData.size_expr_addr);

    PRINTOFF(FDWait.tv_sec);
    PRINTOFF(FDWait.tv_nsec);
    PRINTOFF(FDWait.has_timeout);
    PRINTOFF(FDWait.nfds);
    PRINTOFF(FDWait.invoke_orig);
    PRINTOFF(FDWait.result);

    PRINTOFF(SegFault.pc);
    PRINTOFF(SegFault.address);
    PRINTOFF(SegFault.fault);

    PRINTOFF(Random.buffer);
    PRINTOFF(Random.buffer_size);

    PRINTOFF(GetCfgBool.key_addr);
    PRINTOFF(GetCfgBool.value);

    PRINTOFF(SymbolicSize.size_addr);

    PRINTOFF(SymbolicBuffer.ptr_addr);
    PRINTOFF(SymbolicBuffer.size_addr);

    PRINTOFF(CopyToUser.user_addr);
    PRINTOFF(CopyToUser.addr);
    PRINTOFF(CopyToUser.count);
    PRINTOFF(CopyToUser.done);
    PRINTOFF(CopyToUser.ret);

    PRINTOFF(UpdateMemoryMap.count);
    PRINTOFF(UpdateMemoryMap.buffer);

    PRINTOFF(currentName);
}

void DecreeMonitor::handleCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize,
                                  S2E_DECREEMON_COMMAND &command) {
    std::string currentName(command.currentName, strnlen(command.currentName, sizeof(command.currentName)));

    bool processSyscall = true;
    if (m_detector && !m_detector->isTracked(state, command.currentPid)) {
        processSyscall = false;
        getDebugStream(state) << "Pid " << hexval(command.currentPid) << " is not tracked. "
                              << "Skipping syscall processing.\n";
    }

    switch (command.Command) {
        case DECREE_SEGFAULT: {
            if (m_firstSegfault) {
                time_t now;
                time(&now);
                m_timeToFirstSegfault = difftime(now, m_startTime);
                m_firstSegfault = false;
            }

            getWarningsStream(state) << "received segfault"
                                     << " type=" << command.SegFault.fault << " pagedir=" << hexval(state->getPageDir())
                                     << " pid=" << hexval(command.currentPid) << " pc=" << hexval(command.SegFault.pc)
                                     << " addr=" << hexval(command.SegFault.address) << " name=" << currentName << "\n";

            // Dont switch state until it finishes and gets killed by bootstrap
            // Need to print a message here to avoid confusion and needless debugging,
            // wondering why the searcher doesn't work anymore.
            getDebugStream(state) << "Blocking searcher until state is terminated\n";
            state->setStateSwitchForbidden(true);

            state->disassemble(getDebugStream(state), command.SegFault.pc, 256);

            onSegFault.emit(state, command.currentPid, command.SegFault.pc);

            if (m_terminateProcessGroupOnSegfault) {
                getWarningsStream(state) << "Terminating process group: received segfault\n";
                killpg(0, SIGTERM);
            }

            if (m_terminateOnSegfault) {
                getDebugStream(state) << "Terminating state: received segfault\n";
                s2e()->getExecutor()->terminateStateEarly(*state, "Segfault");
            }
        } break;

        case DECREE_PROCESS_LOAD: {
            handleProcessLoad(state, command.ProcessLoad);
        } break;

        case DECREE_READ_DATA: {
            if (processSyscall) {
                handleReadData(state, command.currentPid, command.Data);
            }
        } break;

        case DECREE_READ_DATA_POST: {
            if (processSyscall) {
                handleReadDataPost(state, command.currentPid, command.DataPost);
            }
        } break;

        case DECREE_WRITE_DATA: {
            if (processSyscall) {
                handleWriteData(state, command.currentPid, command.WriteData);
            }
        } break;

        case DECREE_FD_WAIT: {
            if (processSyscall) {
                handleFdWait(state, command, guestDataPtr);
            }
        } break;

        case DECREE_RANDOM: {
            if (processSyscall) {
                handleRandom(state, command.currentPid, command.Random);
            }
        } break;

        case DECREE_CONCOLIC_ON: {
            getDebugStream(state) << "Turning concolic execution on\n";
            DECLARE_PLUGINSTATE(DecreeMonitorState, state);
            plgState->m_concolicMode = true;
            plgState->m_invokeOriginalSyscalls = true;
        } break;

        case DECREE_CONCOLIC_OFF: {
            getDebugStream(state) << "Turning concolic execution off\n";
            DECLARE_PLUGINSTATE(DecreeMonitorState, state);
            plgState->m_concolicMode = false;
            plgState->m_invokeOriginalSyscalls = false;
        } break;

        case DECREE_GET_CFG_BOOL: {
            handleGetCfgBool(state, command.currentPid, command.GetCfgBool);
            bool ok = state->mem()->writeMemoryConcrete(guestDataPtr, &command, sizeof(command));
            s2e_assert(state, ok, "Failed to write memory");
        } break;

        case DECREE_HANDLE_SYMBOLIC_ALLOCATE_SIZE: {
            if (processSyscall) {
                handleSymbolicAllocateSize(state, command.currentPid, command.SymbolicSize);
            }
        } break;

        case DECREE_HANDLE_SYMBOLIC_TRANSMIT_BUFFER: {
            if (processSyscall) {
                handleSymbolicTransmitBuffer(state, command.currentPid, command.SymbolicBuffer);
            }
        } break;

        case DECREE_HANDLE_SYMBOLIC_RECEIVE_BUFFER: {
            if (processSyscall) {
                handleSymbolicReceiveBuffer(state, command.currentPid, command.SymbolicBuffer);
            }
        } break;

        case DECREE_HANDLE_SYMBOLIC_RANDOM_BUFFER: {
            if (processSyscall) {
                handleSymbolicRandomBuffer(state, command.currentPid, command.SymbolicBuffer);
            }
        } break;

        case DECREE_COPY_TO_USER: {
            if (processSyscall) {
                handleCopyToUser(state, command.currentPid, command.CopyToUser);
            }
        } break;

        case DECREE_UPDATE_MEMORY_MAP: {
            if (processSyscall) {
                handleUpdateMemoryMap(state, command.currentPid, command.UpdateMemoryMap);
            }
        } break;

        case DECREE_SET_CB_PARAMS: {
            handleSetParams(state, command.currentPid, command.CbParams);
            if (!state->writeMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
                // Do not kill the state in case of an error here. This would prevent
                // any exploration at all.
                //
                // Incorrect seed might make fuzzer's task replaying S2E's test cases
                // a bit harder, it's not a show stopper.
                s2e_warn_assert(state, false, "Could not write new seed params");
            }
        } break;
    }
}

bool DecreeMonitor::isReadFd(uint32_t fd) {
    // fd 0 and 1 can both be read from interchangeably in CBs,
    // 3 is for cb-test, >=4 is for multibin CBs.
    if (fd == 0 || fd == 1) {
        return true;
    } else {
        return false;
    }
}

bool DecreeMonitor::isWriteFd(uint32_t fd) {
    // fd 0 and 1 can both be written to interchangeably in CBs,
    // 3 is for cb-test, >=4 is for multibin CBs.
    if (fd == 0 || fd == 1) {
        return true;
    } else {
        return false;
    }
}

} // namespace plugins
} // namespace s2e
