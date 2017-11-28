///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <algorithm>
#include <map>
#include <set>
#include <vector>

#include <s2e/cpu.h>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "StackMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(StackMonitor, "Traces stack usage by modules", "", "OSMonitor", "ProcessExecutionDetector");

///
/// \brief Represents a runtime stack.
///
/// Each thread within a process has its own runtime stack. This stack grows from its highest address (the "bound") to
/// a lower address. The stack is made up of individual stack frames, which are typically accessed via a stack pointer
/// ("sp").
///
/// Internally, this class uses an \c std::vector rather than an \c std::stack becuase it allows us to iterate over the
/// frames. As a consequence of this, the "top" stack frame is located at the end of the \c std::vector. Therefore:
///
/// * \c std::vector.back is equivalent to accessing the top of the stack (\c std::stack.top)
/// * \c std::vector.push_back is equivalent to pushing a new frame onto the top of the stack (\c std::stack.push)
/// * \c std::vector.pop_back is equivalent to popping a frame off the top of the stack (\c std::stack.pop)
///
class Stack {
public:
    /// Create a new stack with an initial stack frame.
    Stack(S2EExecutionState *state, uint64_t bound, uint64_t sp, uint64_t pc, uint64_t function);

    /// Get the stack bound (i.e. the highest address of this stack).
    uint64_t getBound() const;

    /// Returns \c true if the stack has no frames.
    bool empty() const;

    ///
    /// \brief Push a new frame onto the stack.
    ///
    /// A new stack frame is created on a function call.
    ///
    /// \param state The execution state.
    /// \param pc The program counter at the time the new stack frame is created.
    /// \param sp The address pointing to the top of the new stack frame.
    /// \param size The size of the new stack frame.
    /// \param function The start address of the function to which the new stack frame belongs.
    ///
    void push(S2EExecutionState *state, uint64_t pc, uint64_t sp, unsigned size, uint64_t function);

    ///
    /// \brief Update the stack by moving the stack pointer.
    ///
    /// This will unwind (i.e. pop frames off) the stack. If necessary, the top stack frame may be resized.
    ///
    void update(S2EExecutionState *state, uint64_t sp);

    ///
    /// Get the stack frame (if any) for the given stack pointer.
    ///
    /// \param sp The stack pointer.
    /// \param frame If a frame containing \c sp is found, it is returned here.
    /// \return \c true if a frame is found, or \c false otherwise.
    ///
    bool getFrame(uint64_t sp, StackFrame &frame) const;

    /// Get a list of all frames in the stack.
    const StackMonitor::CallStack &getFrames() const;

    friend llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const Stack &stack);

private:
    /// Maintain a pointer to the \c StackMonitor plugin so we can emit signals from it.
    StackMonitor *m_stackMonitor;

    /// The highest address of the stack.
    uint64_t m_bound;

    /// The frames that make up the stack.
    StackMonitor::CallStack m_frames;
};

///
/// \brief The \c StackMonitor plugin state.
///
/// This tracks the runtime stack for each PID/TID pair of interest.
///
class StackMonitorState : public PluginState {

public:
    StackMonitorState();
    virtual ~StackMonitorState(){};

    static PluginState *factory(Plugin *p, S2EExecutionState *state);
    StackMonitorState *clone() const;

    /// Register a function at address \c callAddr as not using a stack frame.
    void registerNoFrameFunction(uint64_t pid, uint64_t callAddr);

    /// Return \c true if the function at address \c callAddr does not use a stack frame.
    bool isNoFrameFunction(uint64_t pid, uint64_t callAddr) const;

    /// Get the stack frame pointed to by the given stack pointer.
    bool getFrame(uint64_t pid, uint64_t sp, StackFrame &frame) const;

    /// Get the call stack (i.e. a list of stack frames) for the given PID/TID.
    bool getCallStack(uint64_t pid, uint64_t tid, StackMonitor::CallStack &callStack) const;

    /// When a thread exits, delete its stack.
    void onThreadExit(uint64_t pid, uint64_t tid);

    /// When a process exits, ensure that all of its stacks (i.e. for each thread) have been deleted.
    void onProcessUnload(S2EExecutionState *state, uint64_t pid);

    ///
    /// \brief Update the given PID/TID's stack.
    ///
    /// \param state The execution state.
    /// \param pid The PID to which the stack belongs.
    /// \param tid The TID (together with the PID) to which the stack belongs.
    /// \param pc The program counter at the point that the stack is being updated.
    /// \param sp The stack pointer pointing to the stack frame being modified.
    /// \param createNewFrame \true if a new stack frame is being created (e.g. due to a function call).
    /// \param function If \c createNewFrame is true, this argument contains the address of the function being called.
    ///
    void update(S2EExecutionState *state, uint64_t pid, uint64_t tid, uint64_t pc, uint64_t sp, bool createNewFrame,
                uint64_t function);

    /// Dump the call stacks to the debug log.
    void dump() const;

private:
    /// Maintain a pointer to the \c OSMonitor plugin so we can get stack information from it
    OSMonitor *m_monitor;

    /// Maintain a pointer to the \c StackMonitor plugin so we can emit signals from it.
    StackMonitor *m_stackMonitor;

    typedef std::pair<uint64_t, uint64_t> PidTidPair;
    typedef std::map<PidTidPair, Stack> Stacks;

    /// Track the runtime stack for each PID/TID pair.
    Stacks m_stacks;

    typedef std::map<uint64_t /* PID */, std::set<uint64_t /* call address */>> NoFrameFunctions;

    /// For each PID, track the addresses that correspond to functions without stack frames.
    NoFrameFunctions m_noFrameFunctions;
};

///////////////////////////////////////////////////////////////////////////////
// Stack
///////////////////////////////////////////////////////////////////////////////

Stack::Stack(S2EExecutionState *state, uint64_t bound, uint64_t sp, uint64_t pc, uint64_t function)
    : m_stackMonitor(g_s2e->getPlugin<StackMonitor>()), m_bound(bound) {
    // Create the initial stack frame
    m_frames.emplace_back(pc, bound, bound - sp + state->getPointerSize(), function);

    m_stackMonitor->onStackFrameCreate.emit(state, sp - state->getPointerSize(), bound);
}

uint64_t Stack::getBound() const {
    return m_bound;
}

bool Stack::empty() const {
    return m_frames.empty();
}

void Stack::push(S2EExecutionState *state, uint64_t pc, uint64_t sp, unsigned size, uint64_t function) {
    // If there are already frames in the stack, check that the newest frame is below the "top" frame (remember that
    // the stack grows from higher to lower addresses)
    if (m_frames.size() > 0) {
        const StackFrame &topFrame = m_frames.back();
        s2e_assert(state, sp < topFrame.top + topFrame.size, "New frame " << hexval(sp)
                                                                          << " is not below the last one at "
                                                                          << hexval(topFrame.top + topFrame.size));
    }

    // Create the new stack frame and push it onto the stack
    m_frames.emplace_back(pc, sp, size, function);

    m_stackMonitor->onStackFrameCreate.emit(state, sp - size, sp);
}

void Stack::update(S2EExecutionState *state, uint64_t sp) {
    s2e_assert(state, !m_frames.empty(), "No stack frames to update");

    if (sp >= m_bound) {
        // This may happen if the stack pointer becomes symbolic. If it does, let it crash itself. The current stack
        // will be unwound and deleted
        g_s2e->getWarningsStream(state) << "Stack pointer " << hexval(sp) << " goes above stack bound "
                                        << hexval(m_bound) << "\n";

        m_bound = sp;
    }

    // Unwind the stack

    StackFrame &topFrame = m_frames.back();

    while (sp > topFrame.top) {
        uint64_t oldBottom = topFrame.top - topFrame.size;
        uint64_t oldTop = topFrame.top;

        m_frames.pop_back();

        if (m_frames.empty()) {
            m_stackMonitor->onStackFrameDelete.emit(state, oldBottom, oldTop, 0, 0);
            return;
        }

        topFrame = m_frames.back();
        m_stackMonitor->onStackFrameDelete.emit(state, oldBottom, oldTop, topFrame.top - topFrame.size, topFrame.top);
    }

    // Resize the current stack frame
    uint64_t oldSize = topFrame.size;
    uint64_t newSize = topFrame.top - sp + state->getPointerSize();

    if (newSize != oldSize) {
        topFrame.size = newSize;

        if (newSize > oldSize) {
            m_stackMonitor->onStackFrameGrow.emit(state, topFrame.top - oldSize, topFrame.top - newSize, topFrame.top);
        } else {
            m_stackMonitor->onStackFrameShrink.emit(state, topFrame.top - oldSize, topFrame.top - newSize,
                                                    topFrame.top);
        }
    }
}

bool Stack::getFrame(uint64_t sp, StackFrame &frame) const {
    // If the given stack pointer is outside our stack, then there is no frame to return
    if (sp >= m_bound) {
        return false;
    }

    // Find the stack frame that contains the given stack pointer
    auto comp = [&](const StackFrame &f) { return sp <= f.top && (sp >= f.top - f.size); };
    auto const &f = std::find_if(m_frames.begin(), m_frames.end(), comp);

    if (f == m_frames.end()) {
        return false;
    } else {
        frame = *f;
        return true;
    }
}

const StackMonitor::CallStack &Stack::getFrames() const {
    return m_frames;
}

llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const Stack &stack) {
    os << "Stack bound=" << hexval(stack.m_bound) << "\n";
    for (auto const &frame : stack.m_frames) {
        os << frame << "\n";
    }

    return os;
}

///////////////////////////////////////////////////////////////////////////////
// StackMonitorState
///////////////////////////////////////////////////////////////////////////////

StackMonitorState::StackMonitorState()
    : m_monitor(static_cast<OSMonitor *>(g_s2e->getPlugin("OSMonitor"))),
      m_stackMonitor(g_s2e->getPlugin<StackMonitor>()) {
}

PluginState *StackMonitorState::factory(Plugin *p, S2EExecutionState *state) {
    return new StackMonitorState();
}

StackMonitorState *StackMonitorState::clone() const {
    return new StackMonitorState();
}

void StackMonitorState::registerNoFrameFunction(uint64_t pid, uint64_t callAddr) {
    m_noFrameFunctions[pid].insert(callAddr);
}

bool StackMonitorState::isNoFrameFunction(uint64_t pid, uint64_t addr) const {
    auto const &noFrameFuncs = m_noFrameFunctions.at(pid);

    return noFrameFuncs.find(addr) != noFrameFuncs.end();
}

bool StackMonitorState::getFrame(uint64_t pid, uint64_t sp, StackFrame &frame) const {
    // XXX Assume that there are very few stacks, so simple iteration is fast enough
    for (auto const &stack : m_stacks) {
        if (stack.first.first != pid) {
            continue;
        }

        if (stack.second.getFrame(sp, frame)) {
            return true;
        }
    }

    return false;
}

bool StackMonitorState::getCallStack(uint64_t pid, uint64_t tid, StackMonitor::CallStack &callStack) const {
    auto const &stackIt = m_stacks.find(std::make_pair(pid, tid));
    if (stackIt == m_stacks.end()) {
        return false;
    }

    callStack = stackIt->second.getFrames();

    return true;
}

void StackMonitorState::onThreadExit(uint64_t pid, uint64_t tid) {
    auto const &stackIt = m_stacks.find(std::make_pair(pid, tid));
    if (stackIt != m_stacks.end()) {
        m_stacks.erase(stackIt);
    }
}

void StackMonitorState::onProcessUnload(S2EExecutionState *state, uint64_t pid) {
    m_noFrameFunctions.erase(pid);

    // The process's stacks should have all been deleted by `StackMonitorState::onThreadExit`. This is just a check to
    // ensure that this actually happened.
    for (auto const &stack : m_stacks) {
        const PidTidPair &pidTid = stack.first;
        s2e_assert(state, pidTid.first != pid, "Stack was not deleted for PID " << hexval(pidTid.first) << " TID "
                                                                                << hexval(pidTid.second) << "\n");
    }
}

void StackMonitorState::update(S2EExecutionState *state, uint64_t pid, uint64_t tid, uint64_t pc, uint64_t sp,
                               bool createNewFrame, uint64_t function) {
    // TODO convert PC to native base
    m_stackMonitor->getDebugStream(state) << "Update"
                                          << " pid=" << hexval(pid) << " tid=" << hexval(tid) << " pc=" << hexval(pc)
                                          << " sp=" << hexval(sp) << " new frame=" << createNewFrame
                                          << " function=" << hexval(function) << "\n";

    PidTidPair pidTid = std::make_pair(pid, tid);
    auto stackIt = m_stacks.find(pidTid);

    if (stackIt == m_stacks.end()) {
        uint64_t stackBase;
        uint64_t stackSize;

        if (!m_monitor->getCurrentStack(state, &stackBase, &stackSize)) {
            m_stackMonitor->getDebugStream(state) << "Could not get current stack\n";
            return;
        }

        m_stacks.insert(std::make_pair(pidTid, Stack(state, stackBase + stackSize, sp, pc, function)));
        stackIt = m_stacks.find(pidTid);

        m_stackMonitor->onStackCreation.emit(state);
    }

    if (createNewFrame) {
        stackIt->second.push(state, pc, sp, state->getPointerSize(), function);
    } else {
        stackIt->second.update(state, sp);
    }

    m_stackMonitor->getDebugStream(state) << stackIt->second << "\n";

    if (stackIt->second.empty()) {
        m_stacks.erase(stackIt);
        m_stackMonitor->onStackDeletion.emit(state);
    }
}

void StackMonitorState::dump() const {
    m_stackMonitor->getDebugStream() << "Dumping stacks\n";

    for (auto const &stack : m_stacks) {
        m_stackMonitor->getDebugStream() << stack.second << "\n";
    }
}

///////////////////////////////////////////////////////////////////////////////
// StackMonitor
///////////////////////////////////////////////////////////////////////////////

void StackMonitor::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();

    m_monitor->onThreadExit.connect(sigc::mem_fun(*this, &StackMonitor::onThreadExit));
    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &StackMonitor::onProcessUnload));

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(sigc::mem_fun(*this, &StackMonitor::onTranslateBlockStart));
    s2e()->getCorePlugin()->onTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &StackMonitor::onTranslateBlockComplete));
}

void StackMonitor::onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread) {
    if (!m_procDetector->isTracked(state, thread.Pid)) {
        return;
    }

    // Delete the stack for this thread
    DECLARE_PLUGINSTATE(StackMonitorState, state);
    plgState->onThreadExit(thread.Pid, thread.Tid);
}

void StackMonitor::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid) {
    if (!m_procDetector->isTracked(state, pid)) {
        return;
    }

    // Process unload implies that all of its threads have exited. Check that this is the case.
    DECLARE_PLUGINSTATE(StackMonitorState, state);
    plgState->onProcessUnload(state, pid);
}

void StackMonitor::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                         uint64_t pc) {
    m_onTranslateRegisterAccessConnection.disconnect();
    m_onTranslateRegisterAccessConnection = s2e()->getCorePlugin()->onTranslateRegisterAccessEnd.connect(
        sigc::mem_fun(*this, &StackMonitor::onTranslateRegisterAccess));
}

void StackMonitor::onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc) {
    m_onTranslateRegisterAccessConnection.disconnect();
}

void StackMonitor::onTranslateRegisterAccess(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc, uint64_t rmask, uint64_t wmask, bool accessesMemory) {
    // Only interested in writes to the stack pointer
    if (!(wmask & (1 << R_ESP))) {
        return;
    }

    // Handle system calls
    if (tb->se_tb_type == TB_SYSENTER) {
        int num_entries = tb->precise_entries;
        s2e_assert(state, num_entries != 0, "TB " << hexval(tb->pc) << " precise entries info is empty");

        tb_precise_pc_t last = tb->precise_pcs[num_entries - 1];
        target_ulong last_pc = tb->pc + last.guest_pc_increment - tb->cs_base;
        if (pc == last_pc) {
            return;
        }
    }

    // Handle function calls

    bool isCall = false;
    target_ulong callEip = 0;

    if (tb->se_tb_type == TB_CALL || tb->se_tb_type == TB_CALL_IND) {
        isCall = true;
        callEip = tb->se_tb_call_eip;
    }

    signal->connect(sigc::bind(sigc::mem_fun(*this, &StackMonitor::onStackPointerModification), isCall, callEip));
}

void StackMonitor::onStackPointerModification(S2EExecutionState *state, uint64_t pc, bool isCall, uint64_t callEip) {
    if (!m_procDetector->isTracked(state)) {
        return;
    }

    DECLARE_PLUGINSTATE(StackMonitorState, state);
    plgState->update(state, m_monitor->getPid(state), m_monitor->getTid(state), pc, state->getSp(), isCall, callEip);
}

void StackMonitor::registerNoFrameFunction(S2EExecutionState *state, uint64_t pid, uint64_t callAddr) {
    DECLARE_PLUGINSTATE(StackMonitorState, state);
    plgState->registerNoFrameFunction(pid, callAddr);
}

bool StackMonitor::getFrame(S2EExecutionState *state, uint64_t sp, StackFrame &frame) const {
    if (!m_procDetector->isTracked(state)) {
        return false;
    }

    DECLARE_PLUGINSTATE(StackMonitorState, state);
    return plgState->getFrame(m_monitor->getPid(state), sp, frame);
}

bool StackMonitor::getCallStack(S2EExecutionState *state, uint64_t pid, uint64_t tid, CallStack &callStack) const {
    DECLARE_PLUGINSTATE(StackMonitorState, state);
    return plgState->getCallStack(pid, tid, callStack);
}

void StackMonitor::update(S2EExecutionState *state, uint64_t pc, uint64_t sp, bool createNewFrame, uint64_t function) {
    if (!m_procDetector->isTracked(state)) {
        return;
    }

    DECLARE_PLUGINSTATE(StackMonitorState, state);
    plgState->update(state, m_monitor->getPid(state), m_monitor->getTid(state), pc, sp, createNewFrame, function);
}

void StackMonitor::dump(S2EExecutionState *state) const {
    DECLARE_PLUGINSTATE(StackMonitorState, state);
    plgState->dump();
}

} // namespace plugins
} // namespace s2e
