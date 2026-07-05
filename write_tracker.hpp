#pragma once

class write_tracker
{
  public:
    static constexpr uint64_t page_size = 0x1000;
    static constexpr uint64_t page_mask = ~(page_size - 1);

    struct dirty_region
    {
        uint64_t start;
        size_t size;
    };

    void record_write(uint64_t address, size_t size)
    {
        const uint64_t first_page = address & page_mask;
        const uint64_t last_page = (address + size - 1) & page_mask;

        for (uint64_t page = first_page; page <= last_page; page += page_size)
            dirty_pages_.insert(page);
    }

    [[nodiscard]] std::vector<dirty_region> get_dirty_regions() const
    {
        if (dirty_pages_.empty())
            return {};

        std::vector<uint64_t> sorted(dirty_pages_.begin(), dirty_pages_.end());
        std::sort(sorted.begin(), sorted.end());

        std::vector<dirty_region> regions;
        uint64_t region_start = sorted[0];
        uint64_t region_end = sorted[0] + page_size;

        for (size_t i = 1; i < sorted.size(); ++i)
        {
            if (sorted[i] <= region_end)
            {
                region_end = sorted[i] + page_size;
            }
            else
            {
                regions.push_back({region_start, static_cast<size_t>(region_end - region_start)});
                region_start = sorted[i];
                region_end = sorted[i] + page_size;
            }
        }
        regions.push_back({region_start, static_cast<size_t>(region_end - region_start)});

        return regions;
    }

    [[nodiscard]] bool has_dirty() const noexcept
    {
        return !dirty_pages_.empty();
    }

    void clear()
    {
        dirty_pages_.clear();
    }

  private:
    std::unordered_set<uint64_t> dirty_pages_;
};
