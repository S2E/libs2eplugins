///
/// Copyright (C) 2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_BASE_FUNCTION_MODELS_H
#define S2E_PLUGINS_BASE_FUNCTION_MODELS_H

#include <klee/Expr.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/MemUtils.h>

using namespace klee;

namespace s2e {

class S2E;
class S2EExecutionState;

namespace plugins {
namespace models {

///
/// \brief Abstract base class for modelling functions that commonly result in state explosion
///
class BaseFunctionModels : public Plugin {
public:
    BaseFunctionModels(S2E *s2e) : Plugin(s2e) {
        initCRCModels();
    }

    virtual ~BaseFunctionModels() {
    }

private:
    void initCRCModels();

protected:
    MemUtils *m_memutils;

    klee::UpdateList *m_crc16_ul;
    klee::UpdateList *m_crc32_ul;

    /// \brief Reads a (concrete) function argument from the stack
    /// \param state S2E execution state
    /// \param param Index of the function argument to read. The first function argument has index 0
    /// \param[out] arg The function argument's value
    /// \return \c true if the function argument is read successfully, \c false otherwise
    bool readArgument(S2EExecutionState *state, unsigned param, uint64_t &arg);

    /// \brief Finds a (possibly symbolic) string's concrete \c NULL terminator and determines the string's maximum
    ///        possible length
    /// \param state S2E execution state
    /// \param str The start address of the string to find the \c NULL terminator in
    /// \param[out] len The maximum possible length of a (possibly symbolic) string
    /// \return \c true if the \c NULL terminator can be found in the given string, or \c false otherwise
    bool findNullChar(S2EExecutionState *state, uint64_t str, size_t &len);

    /// \brief Helper method for constructing a symbolic expression of a string's length
    /// \param state S2E execution state
    /// \param str The start address of the string to calculate the string length of
    /// \param len The concrete length of the string (which is also the maximum possible length of a string)
    /// \param[out] retExpr The symbolic expression that describes the length of a (possibly symbolic) string
    /// \return \c true if the string length expression can be constructed, or \c false otherwise
    bool buildStrlenExpr(S2EExecutionState *state, uint64_t str, size_t len, ref<Expr> &retExpr);

    /// \brief Helper function for comparing two strings
    /// \param state S2E execution state
    /// \param str1 Start address of the first string
    /// \param str2 Start address of the second string
    /// \param len The concrete length of the string (which is also the maximum possible length of a symbolic string)
    /// \param[out] retExpr The symbolic expression that describes the string comparison result. The comparison result
    /// can be calculated by examining each byte of the two strings as follows:
    ///
    /// - If str1[0] < str2[0], then retExpr = -1
    /// - If str1[0] > str2[0], then retExpr = +1
    /// - If str1[0] == str2[0], then check whether str1[1] is '\0'. If yes, the result will be 0. Otherwise we need to
    ///   perform the same checks on (str1[1], str2[1]), (str1[2], str2[2]), ..., (str1[len - 1], str2[len - 1])
    bool buildStrcmpExpr(S2EExecutionState *state, uint64_t str1, uint64_t str2, size_t len, ref<Expr> &retExpr);

    bool buildStrcatExpr(S2EExecutionState *state, uint64_t dest, uint64_t src, size_t len, bool isNcat,
                         ref<Expr> &retExpr);

    //
    // String functions (including wide strings)
    //

    bool strcpyHelper(S2EExecutionState *state, uint64_t dest, uint64_t src, ref<Expr> &retExpr);
    bool strncpyHelper(S2EExecutionState *state, uint64_t dest, uint64_t src, size_t n, ref<Expr> &retExpr);
    bool strlenHelper(S2EExecutionState *state, uint64_t str, ref<Expr> &retExpr);
    bool strcmpHelper(S2EExecutionState *state, uint64_t str1, uint64_t str2, ref<Expr> &retExpr);
    bool strncmpHelper(S2EExecutionState *state, uint64_t str1, uint64_t str2, size_t n, ref<Expr> &retExpr);
    bool strcatHelper(S2EExecutionState *state, uint64_t dest, uint64_t src, ref<Expr> &retExpr);
    bool strncatHelper(S2EExecutionState *state, uint64_t dest, uint64_t src, size_t n, ref<Expr> &retExpr);

    //
    // Memory functions
    //

    bool memcmpHelper(S2EExecutionState *state, uint64_t s1, uint64_t s2, size_t n, ref<Expr> &retExpr);
    bool memcpyHelper(S2EExecutionState *state, uint64_t dest, uint64_t src, size_t n, ref<Expr> &retExpr);

    //
    // CRC functions
    //

    ref<Expr> crc32(const ref<Expr> &initialCrc, const std::vector<ref<Expr>> &input, bool xorResult);
    ref<Expr> crc16(const ref<Expr> &initialCrc, const std::vector<ref<Expr>> &input);
};

} // namespace models
} // namespace plugins
} // namespace s2e

#endif
