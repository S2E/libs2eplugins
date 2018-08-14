///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _LUA_S2E_ANNOTATION_STATE_

#define _LUA_S2E_ANNOTATION_STATE_

#include "Lua.h"

namespace s2e {
namespace plugins {

class LuaAnnotationState {
private:
    bool m_exitCpuLoop;

public:
    static const char className[];
    static Lunar<LuaAnnotationState>::RegType methods[];

    LuaAnnotationState(lua_State *L) : LuaAnnotationState() {
    }

    LuaAnnotationState() : m_exitCpuLoop(false) {
    }

    bool exitCpuLoop() const {
        return m_exitCpuLoop;
    }

    int setExitCpuLoop(lua_State *L);
};
} // namespace plugins
} // namespace s2e

#endif
