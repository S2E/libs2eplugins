///
/// Copyright (C) 2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>
#include <s2e/function_models/commands.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>

#include <klee/Expr.h>
#include <klee/util/ExprTemplates.h>

#include "BaseFunctionModels.h"

namespace s2e {
namespace plugins {
namespace models {

bool BaseFunctionModels::readArgument(S2EExecutionState *state, unsigned param, uint64_t &arg) {
    target_ulong ret;

    uint64_t addr = state->regs()->getSp() + (param + 1) * state->getPointerSize();

    // First check if argument is symbolic
    ref<Expr> readArg = state->mem()->read(addr, state->getPointerWidth());
    if (!isa<ConstantExpr>(readArg)) {
        getDebugStream(state) << "Argument " << param << " at " << hexval(addr) << " is symbolic\n";
        return false;
    }

    // If not, read concrete value
    bool ok = state->readPointer(addr, ret);

    if (!ok) {
        getDebugStream(state) << "Failed to read argument " << param << " at " << hexval(addr) << "\n";
        return false;
    }

    arg = ret;
    return true;
}

bool BaseFunctionModels::findNullChar(S2EExecutionState *state, Expr::Width charWidth, uint64_t str, size_t &len) {
    assert(str);

    const unsigned charSize = charWidth / CHAR_BIT;
    getDebugStream(state) << "Searching for NULL at " << hexval(str) << "\n";

    Solver *solver = s2e()->getExecutor()->getSolver(*state);
    const ref<Expr> nullByteExpr = E_CONST('\0', charWidth);

    // The amount to increment each next character by depends on the character width, which can be either a
    // single char or a wide char
    for (len = 0; len < MAX_STRLEN; len += charSize) {
        assert(str <= UINT64_MAX - len);
        ref<Expr> charExpr = m_memutils->read(state, str + len, charWidth);

        if (charExpr.isNull()) {
            getDebugStream(state) << "Failed to read char " << len << " of string " << hexval(str) << "\n";
            return false;
        }

        ref<Expr> isNullByteExpr = E_EQ(charExpr, nullByteExpr);
        Query query(state->constraints, isNullByteExpr);

        bool truth;
        bool res = solver->mustBeTrue(query, truth);
        if (res && truth) {
            break;
        }
    }

    // Length is in bytes. Convert it to number of characters
    len /= charSize;

    if (len == MAX_STRLEN) {
        getDebugStream(state) << "Could not find NULL char\n";
        return false;
    }

    getDebugStream(state) << "Max length " << len << " chars\n";

    return true;
}

bool BaseFunctionModels::buildStrlenExpr(S2EExecutionState *state, Expr::Width charWidth, uint64_t str, size_t len,
                                         ref<Expr> &retExpr) {
    const unsigned charSize = charWidth / CHAR_BIT;
    const Expr::Width pointerWidth = state->getPointerWidth();
    const ref<Expr> nullByteExpr = E_CONST('\0', charWidth);

    retExpr = E_CONST(len, pointerWidth);

    // The given length is in characters, but at this stage we are operating on bytes
    for (int i = (len * charSize) - charSize; i >= 0; i -= charSize) {
        ref<Expr> charExpr = m_memutils->read(state, str + i, charWidth);
        if (charExpr.isNull()) {
            getDebugStream(state) << "Failed to read char " << i << " of string " << hexval(str) << "\n";
            return false;
        }

        retExpr = E_ITE(E_EQ(charExpr, nullByteExpr), E_CONST(i, pointerWidth), retExpr);
    }

    return true;
}

bool BaseFunctionModels::buildStrcmpExpr(S2EExecutionState *state, Expr::Width charWidth, uint64_t str1, uint64_t str2,
                                         size_t len, ref<Expr> &retExpr) {
    getDebugStream(state) << "Comparing " << len << " chars\n";

    if (!str1 || !str2) {
        getDebugStream(state) << "Got NULL input\n";
        return false;
    }

    const unsigned charSize = charWidth / CHAR_BIT;
    const Expr::Width pointerWidth = state->getPointerWidth();
    assert(pointerWidth == Expr::Int32 && "-1 representation becomes wrong");

    if (len == 0) {
        retExpr = E_CONST(0, pointerWidth);
        return true;
    }

    //
    // Assemble expression
    //

    const ref<Expr> nullByteExpr = E_CONST('\0', charWidth);
    const ref<Expr> retZeroExpr = E_CONST(0, pointerWidth);

    for (int i = (len * charSize) - charSize; i >= 0; i -= charSize) { // also compare NULL char
        ref<Expr> char1Expr = m_memutils->read(state, str1 + i, charWidth);
        if (char1Expr.isNull()) {
            getDebugStream(state) << "Failed to read char " << i << " of string " << hexval(str1) << "\n";
            return false;
        }

        ref<Expr> char2Expr = m_memutils->read(state, str2 + i, charWidth);
        if (char2Expr.isNull()) {
            getDebugStream(state) << "Failed to read char " << i << " of string " << hexval(str2) << "\n";
            return false;
        }

        ref<Expr> subRes = E_SUB(E_ZE(char1Expr, pointerWidth), E_ZE(char2Expr, pointerWidth));
        if ((unsigned) i == (len * charSize) - charSize) {
            retExpr = E_ITE(E_GT(char1Expr, char2Expr), subRes, retZeroExpr);
            retExpr = E_ITE(E_LT(char1Expr, char2Expr), subRes, retExpr);
        } else {
            retExpr = E_ITE(E_AND(E_EQ(char1Expr, nullByteExpr), E_EQ(char2Expr, nullByteExpr)), retZeroExpr, retExpr);
            retExpr = E_ITE(E_GT(char1Expr, char2Expr), subRes, retExpr);
            retExpr = E_ITE(E_LT(char1Expr, char2Expr), subRes, retExpr);
        }
    }

    return true;
}

///
/// \brief Helper function for functions that need to concatenate two strings
///
///      ----------------------------------------------
/// dest | A | B | C | D | E | F | G | H | I | J |'\0'|
///      ----------------------------------------------
///
///      ----------------------------------------------
/// src  | a | b | c | d | e | f | g | h | i | j |'\0'|
///      ----------------------------------------------
///
/// As the two strings could both be symbolic, the lengths of these two strings cannot be determined. Therefore the
/// final concatenated string could have multiple lengths. For example, if the length of dest and src are 3 and 4
/// respectively:
///
///      ------------------------------------
/// dest | A | B | C |'\0'|  |  |  |  |  |  |
///      ------------------------------------
///
///      -------------------------------------
/// src  | a | b | c | d |'\0'|  |  |  |  |  |
///      -------------------------------------
///
/// The result would be:
///
///      ------------------------------------------
/// dest | A | B | C | a | b | c | d |'\0'| I | J |
///      ------------------------------------------
///
/// Therefore, when given a byte of dest string, for example, dest[4], if symlen_dest can exceed 4, then we just
/// keep dest[4] unmodified, otherwise it will be overwritten by src[position] (or '\0' when using 'strncat'), which
/// can be illustrated as follows (note that symlen refers to the symbolic length and conlen refers to the concrete
/// length):
///
/// \code
///     if (symlen_dest + 0 == 4) {
///        if (symlen_src == 0), then: dest[4] = '\0';
///        if (symlen_src > 0),  then: dest[4] = dest[4]; // dest[4] == '\0'
///        return;
///     }
///     if (symlen_dest + 1 == 4) {
///        if (symlen_src == 1), then: dest[4] = '\0';
///        if (symlen_src > 1),  then: dest[4] = dest[4];
///        if (symlen_src < 1),  then: dest[4] = src[1];
///        return;
///     }
///     .
///     .
///     .
///     if (symlen_dest + 4 == 4) {
///        if (symlen_src == 4), then: dest[4] = '\0';
///        if (symlen_src > 4),  then: dest[4] = dest[4];
///        if (symlen_src < 4),  then: dest[4] = src[4];
///        return;
///     }
/// \endcode
///
/// This can be formulated as:
///
/// \code
/// for i in range[0, conlen_dest + conlen_src)
///    for j in range[0, i]
///      if (i - j == symlen_dest), then
///          if   (symlen_src == j), then: dest[i] = '\0';
///          elif (symlen_src < j),  then: dest[i] = dest[i];
///          else (symlen_src > j),  then: dest[i] = ncat; // ncat = (srclen > n) ? src[j] : null; or ncat = srcExpr;
///          fi
///      fi
///     done
/// done
/// \endcode
///
bool BaseFunctionModels::buildStrcatExpr(S2EExecutionState *state, Expr::Width charWidth, uint64_t dest, uint64_t src,
                                         size_t len, bool isNcat, ref<Expr> &retExpr) {
    size_t destLen;
    if (!findNullChar(state, charWidth, dest, destLen)) {
        getDebugStream(state) << "Failed to find NULL char in string " << hexval(dest) << "\n";
        return false;
    }

    ref<Expr> destLenExpr;
    if (!buildStrlenExpr(state, charWidth, dest, destLen, destLenExpr)) {
        getDebugStream(state) << "Failed to build length expression for string " << hexval(dest) << "\n";
        return false;
    }

    size_t srcLen;
    if (!findNullChar(state, charWidth, src, srcLen)) {
        getDebugStream(state) << "Failed to find NULL char in string " << hexval(src) << "\n";
        return false;
    }

    ref<Expr> srcLenExpr;
    if (!buildStrlenExpr(state, charWidth, src, srcLen, srcLenExpr)) {
        getDebugStream(state) << "Failed to build length expression for string " << hexval(src) << "\n";
        return false;
    }

    const unsigned charSize = charWidth / CHAR_BIT;
    const ref<Expr> nullByteExpr = E_CONST('\0', charWidth);
    const Expr::Width width = destLenExpr.get()->getWidth();
    retExpr = E_CONST(dest, width);

    // FIXME: O(n2)
    for (int i = (destLen + len) * charSize; i >= 0; i -= charSize) {
        ref<Expr> destExpr = m_memutils->read(state, dest + i, charWidth);
        if (destExpr.isNull()) {
            getDebugStream(state) << "Failed to read char " << i << " of string " << hexval(dest) << "\n";
            return false;
        }

        ref<Expr> firstOrderCond = E_GT(destLenExpr, E_CONST(i, width));
        ref<Expr> writeExpr, subWrite = nullByteExpr;

        // construct subWrite expression
        for (int j = 0; j <= i; j += charSize) {
            ref<Expr> destLenConds = E_EQ(destLenExpr, E_CONST(i - j, width));
            ref<Expr> srcLenCondsEq = E_EQ(srcLenExpr, E_CONST(j, width));
            ref<Expr> srcLenCondsLower = E_LT(srcLenExpr, E_CONST(j, width));

            ref<Expr> srcExpr = m_memutils->read(state, src + j, charWidth);
            if (srcExpr.isNull()) {
                getDebugStream(state) << "Failed to read char " << j << " of string " << hexval(src) << "\n";
                return false;
            }

            ref<Expr> ncat =
                isNcat ? E_ITE(E_LT(srcLenExpr, E_CONST((int) len, width)), nullByteExpr, srcExpr) : srcExpr;
            ref<Expr> secondOrder = E_ITE(srcLenCondsEq, nullByteExpr, E_ITE(srcLenCondsLower, destExpr, ncat));

            subWrite = E_ITE(destLenConds, secondOrder, subWrite);
        }

        writeExpr = E_ITE(firstOrderCond, destExpr, subWrite);
        if (!state->mem()->write(dest + i, writeExpr)) {
            getDebugStream(state) << "Failed to write to destination string\n";
            return false;
        }
    }

    if (!state->mem()->write(dest + destLen + len, nullByteExpr)) {
        getDebugStream(state) << "Failed to write to NULL terminator\n";
        return false;
    }

    return true;
}

///
/// \brief A function model for char* strcpy(char *dest, const char *src)
///
/// Function Model:
///     For each memory index, i, from 0 to strlen(src) - 1, byte located at
///     src[i] will be written to dest[i] only if there is no terminating null
///     byte before src[i]. The address of the destination string is returned.
///
///     I.e.
///     \code
///     dest[i] = (src[0] != '\0' && src[1] != '\0' && ... && src[i-1] != '\0') ? src[i] : dest[i]
///     \endcode
///     For i = 0, we just perform:
///     \code
///     dest[0] = src[0]
///     \endcode
///
bool BaseFunctionModels::strcpyHelper(S2EExecutionState *state, Expr::Width charWidth, uint64_t dest, uint64_t src,
                                      ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling " << (charWidth == Expr::Int8 ? "str" : "wcs") << "cpy(" << hexval(dest) << ", "
                          << hexval(src) << ")\n";

    // Calculate the length of the source string
    size_t len;
    if (!findNullChar(state, charWidth, src, len)) {
        getDebugStream(state) << "Failed to find NULL char in string " << hexval(src) << "\n";
        return false;
    }

    //
    // Perform the string copy. The address of the destination string is returned
    //

    const unsigned charSize = charWidth / CHAR_BIT;
    const ref<Expr> nullByteExpr = E_CONST('\0', charWidth);
    ref<Expr> accExpr = E_CONST(1, Expr::Bool);

    retExpr = E_CONST(dest, state->getPointerWidth());

    for (unsigned i = 0; i < len * charSize; i += charSize) {
        ref<Expr> destExpr = m_memutils->read(state, dest + i, charWidth);
        if (destExpr.isNull()) {
            getDebugStream(state) << "Failed to read char " << i << " of string " << hexval(dest) << "\n";
            return false;
        }

        ref<Expr> srcExpr = m_memutils->read(state, src + i, charWidth);
        if (srcExpr.isNull()) {
            getDebugStream(state) << "Failed to read char " << i << " of string " << hexval(src) << "\n";
            return false;
        }

        ref<Expr> writeExpr = E_ITE(accExpr, srcExpr, destExpr);
        if (!state->mem()->write(dest + i, writeExpr)) {
            getDebugStream(state) << "Failed to write to destination string\n";
            return false;
        }

        accExpr = E_AND(E_NOT(E_EQ(srcExpr, nullByteExpr)), accExpr);
    }

    if (!state->mem()->write(dest + (len * charSize), nullByteExpr)) {
        getDebugStream(state) << "Failed to write to terminate byte\n";
        return false;
    }

    return true;
}

///
/// \brief A function model for char* strncpy(char *dest, const char *src, size_t n)
///
/// Function Model:
///     For each memory index i, from 0 to min(n-1, strlen(src) - 1), byte
///     located at src[i] will be written to dest[i] only if there is no
///     terminating null byte before src[i]. If strlen(src) is less than n,
///     then pad with null bytes. The address of the destination string is returned
///
///     I.e.
///     \code
///     dest[i] = (src[0] != '\0' && src[1] != '\0' && ... && src[i-1] != '\0') ? src[i] : '\0'
///     \endcode
///     For i = 0, we just perform:
///     \code
///     dest[0] = src[0]
///     \endcode
///
bool BaseFunctionModels::strncpyHelper(S2EExecutionState *state, Expr::Width charWidth, uint64_t dest, uint64_t src,
                                       size_t n, ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling " << (charWidth == Expr::Int8 ? "str" : "wcs") << "ncpy(" << hexval(dest) << ", "
                          << hexval(src) << ", " << n << ")\n";

    //
    // Perform the string copy. The address of the destination string is returned
    //

    const unsigned charSize = charWidth / CHAR_BIT;
    const ref<Expr> nullByteExpr = E_CONST('\0', charWidth);
    ref<Expr> accExpr = E_CONST(1, Expr::Bool);

    retExpr = E_CONST(dest, state->getPointerWidth());

    for (unsigned i = 0; i < n * charSize; i += charSize) {
        ref<Expr> srcExpr = m_memutils->read(state, src + i, charWidth);
        if (srcExpr.isNull()) {
            getDebugStream(state) << "Failed to read char " << i << " of string " << hexval(src) << "\n";
            return false;
        }

        // Null padding
        ref<Expr> writeExpr = E_ITE(accExpr, srcExpr, nullByteExpr);

        if (!state->mem()->write(dest + i, writeExpr)) {
            getDebugStream(state) << "Failed to write to destination string\n";
            return false;
        }

        accExpr = E_AND(E_NOT(E_EQ(srcExpr, nullByteExpr)), accExpr);
    }

    return true;
}

///
/// \brief A helper function for functions that need to obtain the length of a string.
///
/// Obtaining the length of a string can be achieved by the following logic:
///
/// \code
/// if (str[0] == '\0')
///     len = 0;
/// else {
///     if (str[1] == '\0')
///         len = 1;
///     else {
///         ... {
///                 if (str[i] == '\0')
///                      len = i;
///                  else {
///                       ...
///                 }
///          ... }
///      }
/// }
/// \endcode
///
bool BaseFunctionModels::strlenHelper(S2EExecutionState *state, Expr::Width charWidth, uint64_t str,
                                      ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling " << (charWidth == Expr::Int8 ? "str" : "wcs") << "len(" << hexval(str) << ")\n";

    if (!str) {
        getDebugStream(state) << "Got NULL input\n";
        return false;
    }

    // Calculate the string length
    size_t len;
    if (!findNullChar(state, charWidth, str, len)) {
        getDebugStream(state) << "Failed to find NULL char in string " << hexval(str) << "\n";
        return false;
    }

    // Assemble the expression
    return buildStrlenExpr(state, charWidth, str, len, retExpr);
}

bool BaseFunctionModels::strcmpHelper(S2EExecutionState *state, Expr::Width charWidth, uint64_t str1, uint64_t str2,
                                      ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling " << (charWidth == Expr::Int8 ? "str" : "wcs") << "cmp(" << hexval(str1) << ", "
                          << hexval(str2) << ")\n";

    // Calculate the maximum possible string lengths

    size_t str1Len;
    if (!findNullChar(state, charWidth, str1, str1Len)) {
        getDebugStream(state) << "Failed to find NULL char in string " << hexval(str1) << "\n";
        return false;
    }

    size_t str2Len;
    if (!findNullChar(state, charWidth, str2, str2Len)) {
        getDebugStream(state) << "Failed to find NULL char in string " << hexval(str2) << "\n";
        return false;
    }

    return buildStrcmpExpr(state, charWidth, str1, str2, std::min(str1Len, str2Len) + 1, retExpr);
}

bool BaseFunctionModels::strncmpHelper(S2EExecutionState *state, Expr::Width charWidth, uint64_t str1, uint64_t str2,
                                       size_t n, ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling " << (charWidth == Expr::Int8 ? "str" : "wcs") << "ncmp(" << hexval(str1) << ", "
                          << hexval(str2) << ", " << n << ")\n";

    // Calculate the maximum possible string lengths

    size_t str1Len;
    if (!findNullChar(state, charWidth, str1, str1Len)) {
        getDebugStream(state) << "Failed to find NULL char in string " << hexval(str1) << "\n";
        return false;
    }

    size_t str2Len;
    if (!findNullChar(state, charWidth, str2, str2Len)) {
        getDebugStream(state) << "Failed to find NULL char in string " << hexval(str2) << "\n";
        return false;
    }

    return buildStrcmpExpr(state, charWidth, str1, str2, std::min(std::min(str1Len, str2Len) + 1, n), retExpr);
}

bool BaseFunctionModels::strcatHelper(S2EExecutionState *state, Expr::Width charWidth, uint64_t dest, uint64_t src,
                                      ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling " << (charWidth == Expr::Int8 ? "str" : "wcs") << "cat(" << hexval(dest) << ", "
                          << hexval(src) << ")\n";

    size_t srcLen;
    if (!findNullChar(state, charWidth, src, srcLen)) {
        getDebugStream(state) << "Failed to find NULL char in string " << hexval(src) << "\n";
        return false;
    }

    return buildStrcatExpr(state, charWidth, dest, src, srcLen, false, retExpr);
}

bool BaseFunctionModels::strncatHelper(S2EExecutionState *state, Expr::Width charWidth, uint64_t dest, uint64_t src,
                                       size_t n, ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling " << (charWidth == Expr::Int8 ? "str" : "wcs") << "ncat(" << hexval(dest) << ", "
                          << hexval(src) << ", " << n << ")\n";
    assert(n && "Strncat of size 0 should be go through the original strncat in libc!");

    return buildStrcatExpr(state, charWidth, dest, src, n, true, retExpr);
}

///
/// \brief A function model for int memcmp(const void *s1, const void *s2, size_t n);
///
/// Function Model:
///     Memcmp has similar logic to strcmp except that we don't need to check the terminating null byte.
///
bool BaseFunctionModels::memcmpHelper(S2EExecutionState *state, uint64_t s1, uint64_t s2, size_t n,
                                      ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling memcmp(" << hexval(s1) << ", " << hexval(s2) << ", " << n << ")\n";

    if (!s1 || !s2 || !n) {
        getDebugStream(state) << "Got NULL input\n";
        return false;
    }

    if (n > MAX_STRLEN) {
        getDebugStream(state) << "memcmp input is too large\n";
        return false;
    }

    //
    // Assemble the expression
    //

    const Expr::Width width = state->getPointerSize() * CHAR_BIT;
    retExpr = E_CONST(0, width);

    for (int i = n - 1; i >= 0; i--) {
        ref<Expr> byte1Expr = m_memutils->read(state, s1 + i);
        if (byte1Expr.isNull()) {
            getDebugStream(state) << "Failed to read byte " << i << " of memory " << hexval(s1) << "\n";
            return false;
        }

        ref<Expr> byte2Expr = m_memutils->read(state, s2 + i);
        if (byte2Expr.isNull()) {
            getDebugStream(state) << "Failed to read byte " << i << " of memory " << hexval(s2) << "\n";
            return false;
        }

        retExpr = E_ITE(E_NEQ(byte1Expr, byte2Expr), E_SUBZE(byte1Expr, byte2Expr, width), retExpr);
    }

    return true;
}

///
/// \brief A function model for void* memcpy(void *dest, const void *src, size_t n);
///
/// Function Model:
///     Memcpy has similar logic to strcpy except that we don't need to check the terminating null byte.
///
bool BaseFunctionModels::memcpyHelper(S2EExecutionState *state, uint64_t dest, uint64_t src, size_t n,
                                      ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling memcpy(" << hexval(dest) << ", " << hexval(src) << ", " << n << ")\n";

    //
    // Perform the memory copy. The address of the destination buffer is returned
    //

    const Expr::Width width = state->getPointerSize() * CHAR_BIT;
    retExpr = E_CONST(dest, width);

    for (unsigned i = 0; i < n; i++) {
        ref<Expr> srcExpr = m_memutils->read(state, src + i);
        if (srcExpr.isNull()) {
            getDebugStream(state) << "Failed to read char " << i << " of memory " << hexval(src) << "\n";
            return false;
        }

        if (!state->mem()->write(dest + i, srcExpr)) {
            getDebugStream(state) << "Failed to write to destination string\n";
            return false;
        }
    }

    return true;
}

} // namespace models
} // namespace plugins
} // namespace s2e
