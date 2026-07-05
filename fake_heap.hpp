#pragma once

class fake_heap
{
  public:
    static constexpr size_t arena_size = 0x0100'0000;
    static constexpr size_t alloc_alignment = 16;

    bool init(uc_engine* uc, uint64_t base_address)
    {
        if (initialized_)
            return true;

        arena_base_ = base_address;
        cursor_ = arena_base_;

        const uc_err err = uc_mem_map(uc, arena_base_, arena_size, UC_PROT_ALL);
        if (err != UC_ERR_OK)
            return false;

        initialized_ = true;
        return true;
    }

    uint64_t alloc(size_t size)
    {
        if (!initialized_ || size == 0)
            return 0;

        size = (size + alloc_alignment - 1) & ~(alloc_alignment - 1);

        if (cursor_ + size > arena_base_ + arena_size)
            return 0;

        const uint64_t ptr = cursor_;
        cursor_ += size;
        alloc_sizes_[ptr] = size;
        return ptr;
    }

    uint64_t calloc_alloc(uc_engine* uc, size_t count, size_t elem_size)
    {
        const size_t total = count * elem_size;
        const uint64_t ptr = alloc(total);
        if (ptr != 0)
        {
            std::vector<uint8_t> zeros(total, 0);
            uc_mem_write(uc, ptr, zeros.data(), total);
        }
        return ptr;
    }

    uint64_t realloc_alloc(uc_engine* uc, uint64_t old_ptr, size_t new_size)
    {
        if (old_ptr == 0)
            return alloc(new_size);

        if (new_size == 0)
            return 0;

        size_t old_size = 0;
        if (const auto it = alloc_sizes_.find(old_ptr); it != alloc_sizes_.end())
            old_size = it->second;

        const uint64_t new_ptr = alloc(new_size);
        if (new_ptr == 0)
            return 0;

        if (old_size > 0)
        {
            const size_t copy_size = std::min(old_size, new_size);
            std::vector<uint8_t> buf(copy_size);
            if (uc_mem_read(uc, old_ptr, buf.data(), copy_size) == UC_ERR_OK)
                uc_mem_write(uc, new_ptr, buf.data(), copy_size);
        }

        return new_ptr;
    }

    void free_alloc(uint64_t) {}

    [[nodiscard]] bool contains(uint64_t address) const noexcept
    {
        return initialized_ && address >= arena_base_ && address < arena_base_ + arena_size;
    }

    void reset(uc_engine* uc)
    {
        if (!initialized_)
            return;

        const size_t used = static_cast<size_t>(cursor_ - arena_base_);
        if (used > 0)
        {
            std::vector<uint8_t> zeros(used, 0);
            uc_mem_write(uc, arena_base_, zeros.data(), used);
        }

        cursor_ = arena_base_;
        alloc_sizes_.clear();
    }

    [[nodiscard]] uint64_t arena_base() const noexcept
    {
        return arena_base_;
    }

    [[nodiscard]] bool is_initialized() const noexcept
    {
        return initialized_;
    }

    static uint64_t compute_base(uint64_t image_map_end, uint64_t stack_start, uint64_t stack_end)
    {
        constexpr uint64_t page_align = 0x10000;
        uint64_t candidate = (image_map_end + page_align - 1) & ~(page_align - 1);

        if (candidate + arena_size > stack_start && candidate < stack_end)
            candidate = (stack_end + page_align - 1) & ~(page_align - 1);

        return candidate;
    }

  private:
    uint64_t arena_base_ = 0;
    uint64_t cursor_ = 0;
    std::unordered_map<uint64_t, size_t> alloc_sizes_;
    bool initialized_ = false;
};
