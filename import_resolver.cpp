#include "global.hpp"

#pragma warning(push, 0)
#include <nalt.hpp>
#include <name.hpp>
#pragma warning(pop)

namespace
{
    int idaapi import_enum_cb(ea_t ea, const char* name, uval_t, void* param)
    {
        auto* map = static_cast<std::unordered_map<uint64_t, std::string>*>(param);
        if (name != nullptr && name[0] != '\0')
            (*map)[ea] = name;
        return 1;
    }

    constexpr auto thunk_jump_types = std::to_array<int>({NN_jmp, NN_jmpfi, NN_jmpni});

    bool is_thunk_jump(int itype)
    {
        for (const int t : thunk_jump_types)
        {
            if (t == itype)
                return true;
        }
        return false;
    }
}

std::unordered_map<uint64_t, std::string> import_resolver::build_import_map()
{
    std::unordered_map<uint64_t, std::string> result;

    const int module_count = import_module_qty();
    for (int i = 0; i < module_count; ++i)
        enum_import_names(i, import_enum_cb, &result);

    // Resolve thunks: functions that are a single JMP to an IAT entry
    std::unordered_map<uint64_t, std::string> thunks;
    const size_t func_count = get_func_qty();
    for (size_t i = 0; i < func_count; ++i)
    {
        const func_t* func = getn_func(i);
        if (func == nullptr)
            continue;

        insn_t insn;
        if (decode_insn(&insn, func->start_ea) <= 0)
            continue;

        if (!is_thunk_jump(insn.itype))
            continue;

        if (insn.Op1.type != o_mem)
            continue;

        if (const auto it = result.find(insn.Op1.addr); it != result.end())
            thunks[func->start_ea] = it->second;
    }

    result.insert(thunks.begin(), thunks.end());
    return result;
}
