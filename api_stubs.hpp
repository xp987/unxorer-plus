#pragma once

namespace api_stubs
{
    namespace detail
    {
        constexpr size_t max_buffer = 0x100000;

        inline uint64_t read_arg(uc_engine* uc, int index)
        {
            static constexpr int regs[] = {UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9};
            uint64_t value = 0;
            if (index < 4)
            {
                uc_reg_read(uc, regs[index], &value);
            }
            else
            {
                uint64_t rsp = 0;
                uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
                uc_mem_read(uc, rsp + 0x20 + static_cast<uint64_t>(index - 4) * 8, &value, sizeof(value));
            }
            return value;
        }

        inline void write_ret(uc_engine* uc, uint64_t value)
        {
            uc_reg_write(uc, UC_X86_REG_RAX, &value);
        }

        inline void stub_malloc(uc_engine* uc, fake_heap& heap)
        {
            const auto size = static_cast<size_t>(read_arg(uc, 0));
            write_ret(uc, heap.alloc(size));
        }

        inline void stub_calloc(uc_engine* uc, fake_heap& heap)
        {
            const auto count = static_cast<size_t>(read_arg(uc, 0));
            const auto size = static_cast<size_t>(read_arg(uc, 1));
            write_ret(uc, heap.calloc_alloc(uc, count, size));
        }

        inline void stub_realloc(uc_engine* uc, fake_heap& heap)
        {
            const auto ptr = read_arg(uc, 0);
            const auto size = static_cast<size_t>(read_arg(uc, 1));
            write_ret(uc, heap.realloc_alloc(uc, ptr, size));
        }

        inline void stub_free(uc_engine* uc, fake_heap& heap)
        {
            heap.free_alloc(read_arg(uc, 0));
            write_ret(uc, 0);
        }

        inline void stub_memcpy(uc_engine* uc, fake_heap&)
        {
            const auto dest = read_arg(uc, 0);
            const auto src = read_arg(uc, 1);
            const auto count = static_cast<size_t>(read_arg(uc, 2));

            if (count > 0 && count <= max_buffer)
            {
                std::vector<uint8_t> buf(count);
                if (uc_mem_read(uc, src, buf.data(), count) == UC_ERR_OK)
                    uc_mem_write(uc, dest, buf.data(), count);
            }
            write_ret(uc, dest);
        }

        inline void stub_memset(uc_engine* uc, fake_heap&)
        {
            const auto dest = read_arg(uc, 0);
            const auto fill = static_cast<uint8_t>(read_arg(uc, 1));
            const auto count = static_cast<size_t>(read_arg(uc, 2));

            if (count > 0 && count <= max_buffer)
            {
                std::vector<uint8_t> buf(count, fill);
                uc_mem_write(uc, dest, buf.data(), count);
            }
            write_ret(uc, dest);
        }

        inline void stub_memcmp(uc_engine* uc, fake_heap&)
        {
            const auto a = read_arg(uc, 0);
            const auto b = read_arg(uc, 1);
            const auto count = static_cast<size_t>(read_arg(uc, 2));

            int result = 0;
            if (count > 0 && count <= max_buffer)
            {
                std::vector<uint8_t> buf_a(count);
                std::vector<uint8_t> buf_b(count);
                if (uc_mem_read(uc, a, buf_a.data(), count) == UC_ERR_OK &&
                    uc_mem_read(uc, b, buf_b.data(), count) == UC_ERR_OK)
                {
                    result = std::memcmp(buf_a.data(), buf_b.data(), count);
                }
            }
            write_ret(uc, static_cast<uint64_t>(static_cast<int64_t>(result)));
        }

        inline void stub_strlen(uc_engine* uc, fake_heap&)
        {
            const auto str = read_arg(uc, 0);
            size_t len = 0;
            uint8_t byte = 1;
            while (len < max_buffer && uc_mem_read(uc, str + len, &byte, 1) == UC_ERR_OK && byte != 0)
                ++len;
            write_ret(uc, len);
        }

        inline void stub_wcslen(uc_engine* uc, fake_heap&)
        {
            const auto str = read_arg(uc, 0);
            size_t len = 0;
            uint16_t ch = 1;
            while (len < max_buffer && uc_mem_read(uc, str + len * 2, &ch, 2) == UC_ERR_OK && ch != 0)
                ++len;
            write_ret(uc, len);
        }

        inline void stub_strcpy(uc_engine* uc, fake_heap&)
        {
            const auto dest = read_arg(uc, 0);
            const auto src = read_arg(uc, 1);
            size_t i = 0;
            uint8_t byte = 0;
            do
            {
                if (i >= max_buffer || uc_mem_read(uc, src + i, &byte, 1) != UC_ERR_OK)
                    break;
                uc_mem_write(uc, dest + i, &byte, 1);
                ++i;
            } while (byte != 0);
            write_ret(uc, dest);
        }

        inline void stub_strncpy(uc_engine* uc, fake_heap&)
        {
            const auto dest = read_arg(uc, 0);
            const auto src = read_arg(uc, 1);
            auto count = static_cast<size_t>(read_arg(uc, 2));
            if (count > max_buffer)
                count = max_buffer;

            bool hit_null = false;
            for (size_t i = 0; i < count; ++i)
            {
                uint8_t byte = 0;
                if (!hit_null && uc_mem_read(uc, src + i, &byte, 1) == UC_ERR_OK && byte != 0)
                    uc_mem_write(uc, dest + i, &byte, 1);
                else
                {
                    hit_null = true;
                    const uint8_t zero = 0;
                    uc_mem_write(uc, dest + i, &zero, 1);
                }
            }
            write_ret(uc, dest);
        }

        inline void stub_wcscpy(uc_engine* uc, fake_heap&)
        {
            const auto dest = read_arg(uc, 0);
            const auto src = read_arg(uc, 1);
            size_t i = 0;
            uint16_t ch = 0;
            do
            {
                if (i >= max_buffer || uc_mem_read(uc, src + i * 2, &ch, 2) != UC_ERR_OK)
                    break;
                uc_mem_write(uc, dest + i * 2, &ch, 2);
                ++i;
            } while (ch != 0);
            write_ret(uc, dest);
        }

        inline void stub_wcsncpy(uc_engine* uc, fake_heap&)
        {
            const auto dest = read_arg(uc, 0);
            const auto src = read_arg(uc, 1);
            auto count = static_cast<size_t>(read_arg(uc, 2));
            if (count > max_buffer)
                count = max_buffer;

            bool hit_null = false;
            for (size_t i = 0; i < count; ++i)
            {
                uint16_t ch = 0;
                if (!hit_null && uc_mem_read(uc, src + i * 2, &ch, 2) == UC_ERR_OK && ch != 0)
                    uc_mem_write(uc, dest + i * 2, &ch, 2);
                else
                {
                    hit_null = true;
                    const uint16_t zero = 0;
                    uc_mem_write(uc, dest + i * 2, &zero, 2);
                }
            }
            write_ret(uc, dest);
        }

        inline void stub_strcat(uc_engine* uc, fake_heap&)
        {
            const auto dest = read_arg(uc, 0);
            const auto src = read_arg(uc, 1);

            size_t dest_len = 0;
            uint8_t byte = 1;
            while (dest_len < max_buffer && uc_mem_read(uc, dest + dest_len, &byte, 1) == UC_ERR_OK && byte != 0)
                ++dest_len;

            size_t i = 0;
            do
            {
                if (dest_len + i >= max_buffer || uc_mem_read(uc, src + i, &byte, 1) != UC_ERR_OK)
                    break;
                uc_mem_write(uc, dest + dest_len + i, &byte, 1);
                ++i;
            } while (byte != 0);
            write_ret(uc, dest);
        }

        inline void stub_wcscat(uc_engine* uc, fake_heap&)
        {
            const auto dest = read_arg(uc, 0);
            const auto src = read_arg(uc, 1);

            size_t dest_len = 0;
            uint16_t ch = 1;
            while (dest_len < max_buffer && uc_mem_read(uc, dest + dest_len * 2, &ch, 2) == UC_ERR_OK && ch != 0)
                ++dest_len;

            size_t i = 0;
            do
            {
                if (dest_len + i >= max_buffer || uc_mem_read(uc, src + i * 2, &ch, 2) != UC_ERR_OK)
                    break;
                uc_mem_write(uc, dest + (dest_len + i) * 2, &ch, 2);
                ++i;
            } while (ch != 0);
            write_ret(uc, dest);
        }

        // RtlZeroMemory(dest, length) — note: 2 args, not 3 like memset
        inline void stub_rtl_zero_memory(uc_engine* uc, fake_heap&)
        {
            const auto dest = read_arg(uc, 0);
            const auto count = static_cast<size_t>(read_arg(uc, 1));
            if (count > 0 && count <= max_buffer)
            {
                std::vector<uint8_t> zeros(count, 0);
                uc_mem_write(uc, dest, zeros.data(), count);
            }
        }

        // RtlFillMemory(dest, length, fill) — different arg order than memset
        inline void stub_rtl_fill_memory(uc_engine* uc, fake_heap&)
        {
            const auto dest = read_arg(uc, 0);
            const auto count = static_cast<size_t>(read_arg(uc, 1));
            const auto fill = static_cast<uint8_t>(read_arg(uc, 2));
            if (count > 0 && count <= max_buffer)
            {
                std::vector<uint8_t> buf(count, fill);
                uc_mem_write(uc, dest, buf.data(), count);
            }
        }

        inline void stub_get_process_heap(uc_engine* uc, fake_heap&)
        {
            constexpr uint64_t fake_handle = 0xBEEF'0000;
            write_ret(uc, fake_handle);
        }

        // HeapAlloc(hHeap, dwFlags, dwBytes) — RCX=heap, RDX=flags, R8=size
        inline void stub_heap_alloc(uc_engine* uc, fake_heap& heap)
        {
            const auto flags = static_cast<uint32_t>(read_arg(uc, 1));
            const auto size = static_cast<size_t>(read_arg(uc, 2));
            uint64_t ptr = heap.alloc(size);
            if (ptr != 0 && (flags & 0x00000008))
            {
                std::vector<uint8_t> zeros(size, 0);
                uc_mem_write(uc, ptr, zeros.data(), size);
            }
            write_ret(uc, ptr);
        }

        // HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes) — RCX=heap, RDX=flags, R8=ptr, R9=size
        inline void stub_heap_realloc(uc_engine* uc, fake_heap& heap)
        {
            const auto old_ptr = read_arg(uc, 2);
            const auto new_size = static_cast<size_t>(read_arg(uc, 3));
            write_ret(uc, heap.realloc_alloc(uc, old_ptr, new_size));
        }

        // VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) — always zero-inits
        inline void stub_virtual_alloc(uc_engine* uc, fake_heap& heap)
        {
            const auto size = static_cast<size_t>(read_arg(uc, 1));
            const uint64_t ptr = heap.alloc(size);
            if (ptr != 0)
            {
                std::vector<uint8_t> zeros(size, 0);
                uc_mem_write(uc, ptr, zeros.data(), size);
            }
            write_ret(uc, ptr);
        }

        // LocalAlloc(uFlags, uBytes) / GlobalAlloc(uFlags, dwBytes)
        inline void stub_local_alloc(uc_engine* uc, fake_heap& heap)
        {
            const auto flags = static_cast<uint32_t>(read_arg(uc, 0));
            const auto size = static_cast<size_t>(read_arg(uc, 1));
            uint64_t ptr = heap.alloc(size);
            if (ptr != 0 && (flags & 0x0040))
            {
                std::vector<uint8_t> zeros(size, 0);
                uc_mem_write(uc, ptr, zeros.data(), size);
            }
            write_ret(uc, ptr);
        }

        using stub_fn = void (*)(uc_engine*, fake_heap&);

        struct stub_entry
        {
            const char* name;
            stub_fn handler;
        };

        // clang-format off
        constexpr stub_entry stub_table[] = {
            {"malloc",          stub_malloc},
            {"calloc",          stub_calloc},
            {"realloc",         stub_realloc},
            {"free",            stub_free},
            {"HeapAlloc",       stub_heap_alloc},
            {"HeapFree",        stub_free},
            {"HeapReAlloc",     stub_heap_realloc},
            {"VirtualAlloc",    stub_virtual_alloc},
            {"VirtualFree",     stub_free},
            {"LocalAlloc",      stub_local_alloc},
            {"LocalFree",       stub_free},
            {"GlobalAlloc",     stub_local_alloc},
            {"GlobalFree",      stub_free},
            {"GetProcessHeap",  stub_get_process_heap},
            {"memcpy",          stub_memcpy},
            {"memmove",         stub_memcpy},
            {"memset",          stub_memset},
            {"memcmp",          stub_memcmp},
            {"strlen",          stub_strlen},
            {"wcslen",          stub_wcslen},
            {"strcpy",          stub_strcpy},
            {"strncpy",         stub_strncpy},
            {"wcscpy",          stub_wcscpy},
            {"wcsncpy",         stub_wcsncpy},
            {"strcat",          stub_strcat},
            {"wcscat",          stub_wcscat},
            {"RtlMoveMemory",   stub_memcpy},
            {"RtlZeroMemory",   stub_rtl_zero_memory},
            {"RtlFillMemory",   stub_rtl_fill_memory},
            {"lstrlenA",        stub_strlen},
            {"lstrlenW",        stub_wcslen},
            {"lstrcpyA",        stub_strcpy},
            {"lstrcpyW",        stub_wcscpy},
            {"lstrcpynA",       stub_strncpy},
            {"lstrcpynW",       stub_wcsncpy},
        };
        // clang-format on

        inline stub_fn find_stub(std::string_view name)
        {
            for (const auto& entry : stub_table)
            {
                if (name == entry.name)
                    return entry.handler;
            }
            return nullptr;
        }
    }

    inline bool try_dispatch(uc_engine* uc, std::string_view import_name, fake_heap& heap)
    {
        if (auto fn = detail::find_stub(import_name); fn != nullptr)
        {
            fn(uc, heap);
            return true;
        }

        // Strip leading underscores and retry (e.g. _malloc → malloc)
        std::string_view stripped = import_name;
        while (!stripped.empty() && stripped.front() == '_')
            stripped.remove_prefix(1);

        if (stripped != import_name)
        {
            if (auto fn = detail::find_stub(stripped); fn != nullptr)
            {
                fn(uc, heap);
                return true;
            }
        }

        // Strip module prefix and retry (e.g. KERNEL32_HeapAlloc → HeapAlloc, msvcrt_malloc → malloc)
        if (const auto pos = import_name.rfind('_'); pos != std::string_view::npos && pos + 1 < import_name.size())
        {
            const auto suffix = import_name.substr(pos + 1);
            if (suffix != stripped)
            {
                if (auto fn = detail::find_stub(suffix); fn != nullptr)
                {
                    fn(uc, heap);
                    return true;
                }
            }
        }

        return false;
    }
}
