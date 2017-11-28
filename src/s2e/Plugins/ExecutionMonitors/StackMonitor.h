///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_STACK_MONITOR_2_H
#define S2E_PLUGINS_STACK_MONITOR_2_H

#include <vector>

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Utils.h>

namespace s2e {

struct ThreadDescriptor;

namespace plugins {

class OSMonitor;
class ProcessExecutionDetector;

/// Represents a single frame on the stack.
struct StackFrame {
    /// Program counter that opened the stack frame (typically a call instruction).
    uint64_t pc;

    /// The top of the stack frame.
    uint64_t top;

    /// The size of the stack frame.
    uint64_t size;

    /// Function to which this frame belongs.
    uint64_t function;

    /// Create a new stack frame
    StackFrame(uint64_t pc_, uint64_t top_, uint64_t size_, uint64_t func)
        : pc(pc_), top(top_), size(size_), function(func) {
    }

    bool operator<(const StackFrame &sf) {
        return top + size <= sf.size;
    }

    friend llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const StackFrame &frame) {
        os << "  Frame pc=" << hexval(frame.pc) << " top=" << hexval(frame.top) << " size=" << hexval(frame.size)
           << " function=" << hexval(frame.function);
        return os;
    }
};

class StackMonitor : public Plugin {
    S2E_PLUGIN

public:
    typedef std::vector<StackFrame> CallStack;
    typedef std::vector<CallStack> CallStacks;

    StackMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    /// Register a function at the given address as not using a stack frame.
    void registerNoFrameFunction(S2EExecutionState *state, uint64_t pid, uint64_t callAddr);

    ///
    /// Get the stack frame pointed to by the given stack pointer.
    ///
    /// \param state The execution state.
    /// \param sp The stack pointer to get the stack frame for.
    /// \param frame The stack frame is returned here.
    /// \return \c true if \c sp points to a valid stack frame, otherwise \c false.
    ///
    bool getFrame(S2EExecutionState *state, uint64_t sp, StackFrame &frame) const;

    ///
    /// Get the call stack for the given process and thread.
    ///
    /// \param state The execution state.
    /// \param pid The PID to retrieve the call stack from.
    /// \param tid The TID to retrieve the call stack from (unused in conjunction with the PID).
    /// \param callStack Return the call stack here (if found).
    /// \return \c true if a call stack for the given PID/TID exists, otherwise \c false.
    ///
    bool getCallStack(S2EExecutionState *state, uint64_t pid, uint64_t tid, CallStack &callStack) const;

    ///
    /// Update the stack in the given execution state.
    ///
    /// If \c createNewFrame is true, then a call to function at address \c function has occurred so a new stack frame
    /// is created and pushed onto the stack. Otherwise the stack is modified (e.g. wound back) depending on the given
    /// stack pointer \c sp.
    ///
    void update(S2EExecutionState *state, uint64_t pc, uint64_t sp, bool createNewFrame, uint64_t function);

    /// Dump the call stacks to the debug log.
    void dump(S2EExecutionState *state) const;

    //
    // Signals
    //

    /// Emitted when a new stack frame is setup (e.g. when execution enters a module of interest).
    sigc::signal<void, S2EExecutionState *> onStackCreation;

    /// Emitted when there are no more stack frames.
    sigc::signal<void, S2EExecutionState *> onStackDeletion;

    /// Emitted when a new stack frame is created.
    sigc::signal<void, S2EExecutionState *, uint64_t /* new base */, uint64_t /* new top */> onStackFrameCreate;

    /// Emitted when a stack frame is resized (made larger).
    sigc::signal<void, S2EExecutionState *, uint64_t /* old base */, uint64_t /* new base */, uint64_t /* top */>
        onStackFrameGrow;

    /// Emitted when a stack frame is resized (made smaller).
    sigc::signal<void, S2EExecutionState *, uint64_t /* old base */, uint64_t /* new base */, uint64_t /* top */>
        onStackFrameShrink;

    /// Emitted when a stack frame is deleted.
    sigc::signal<void, S2EExecutionState *, uint64_t /* old base */, uint64_t /* old top */, uint64_t /* new bottom */,
                 uint64_t /* new top */>
        onStackFrameDelete;

private:
    OSMonitor *m_monitor;
    ProcessExecutionDetector *m_procDetector;

    sigc::connection m_onTranslateRegisterAccessConnection;

    void onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread);
    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid);
    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc);
    void onTranslateRegisterAccess(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                                   uint64_t rmask, uint64_t wmask, bool accessesMemory);
    void onStackPointerModification(S2EExecutionState *state, uint64_t pc, bool isCall, uint64_t callEip);
};
} // namespace plugins
} // namespace s2e

#endif
