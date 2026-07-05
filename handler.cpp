#include "global.hpp"
#include "aes_impl.hpp"

namespace
{
    bool read_operand(uc_engine* uc, const op_t& op, uint8_t* dest, int size)
    {
        if (op.type == o_mem || op.type == o_displ)
        {
            const uint64_t ea = vector_operations::calculate_effective_address(uc, op);
            return uc_mem_read(uc, ea, dest, size) == UC_ERR_OK;
        }
        if (op.type == o_reg)
        {
            if (register_mapper::vector_reg_size(op.reg) > 0)
            {
                return vector_operations::read_vector_register(uc, op.reg, dest, size);
            }
            const int uni_reg = register_mapper::ida_to_unicorn(op.reg);
            if (uni_reg != 0)
            {
                uint64_t val = 0;
                if (uc_reg_read(uc, uni_reg, &val) == UC_ERR_OK)
                {
                    std::memcpy(dest, &val, std::min<size_t>(size, 8));
                    return true;
                }
            }
        }
        if (op.type == o_imm)
        {
            std::memcpy(dest, &op.value, std::min<size_t>(size, 8));
            return true;
        }
        return false;
    }

    bool write_operand(uc_engine* uc, const op_t& op, const uint8_t* src, int size)
    {
        if (op.type == o_mem || op.type == o_displ)
        {
            const uint64_t ea = vector_operations::calculate_effective_address(uc, op);
            return uc_mem_write(uc, ea, src, size) == UC_ERR_OK;
        }
        if (op.type == o_reg)
        {
            if (register_mapper::vector_reg_size(op.reg) > 0)
            {
                return vector_operations::write_vector_register(uc, op.reg, src, size);
            }
            const int uni_reg = register_mapper::ida_to_unicorn(op.reg);
            if (uni_reg != 0)
            {
                uint64_t val = 0;
                if (size == 4)
                {
                    uint32_t val32 = 0;
                    std::memcpy(&val32, src, 4);
                    val = val32;
                }
                else
                {
                    std::memcpy(&val, src, std::min<size_t>(size, 8));
                }
                return uc_reg_write(uc, uni_reg, &val) == UC_ERR_OK;
            }
        }
        return false;
    }

    void resolve_operands_2_or_3(uc_engine* uc, const insn_t& insn, uint8_t* lhs, uint8_t* rhs, int size)
    {
        if (insn.Op3.type != o_void)
        {
            read_operand(uc, insn.Op2, lhs, size);
            read_operand(uc, insn.Op3, rhs, size);
        }
        else
        {
            read_operand(uc, insn.Op1, lhs, size);
            read_operand(uc, insn.Op2, rhs, size);
        }
    }

    void handle_move(uc_engine* uc, const insn_t& insn)
    {
        int size = 16;
        if (insn.itype == NN_movd || insn.itype == NN_vmovd)
            size = 4;
        else if (insn.itype == NN_movq || insn.itype == NN_vmovq)
            size = 8;
        else
        {
            int reg_size = register_mapper::vector_reg_size(insn.Op1.reg);
            if (reg_size == 0)
                reg_size = register_mapper::vector_reg_size(insn.Op2.reg);
            if (reg_size > 0)
                size = reg_size;
        }

        std::array<uint8_t, 32> buf{};
        if (read_operand(uc, insn.Op2, buf.data(), size))
        {
            write_operand(uc, insn.Op1, buf.data(), size);
        }
    }

    void handle_xor(uc_engine* uc, const insn_t& insn)
    {
        const int size = register_mapper::vector_reg_size(insn.Op1.reg);
        if (size <= 0)
            return;

        std::array<uint8_t, 32> lhs{};
        std::array<uint8_t, 32> rhs{};
        resolve_operands_2_or_3(uc, insn, lhs.data(), rhs.data(), size);

        std::array<uint8_t, 32> res{};
        for (int i = 0; i < size; ++i)
            res[i] = lhs[i] ^ rhs[i];

        write_operand(uc, insn.Op1, res.data(), size);
    }

    void handle_and(uc_engine* uc, const insn_t& insn)
    {
        const int size = register_mapper::vector_reg_size(insn.Op1.reg);
        if (size <= 0)
            return;

        std::array<uint8_t, 32> lhs{};
        std::array<uint8_t, 32> rhs{};
        resolve_operands_2_or_3(uc, insn, lhs.data(), rhs.data(), size);

        std::array<uint8_t, 32> res{};
        for (int i = 0; i < size; ++i)
            res[i] = lhs[i] & rhs[i];

        write_operand(uc, insn.Op1, res.data(), size);
    }

    void handle_or(uc_engine* uc, const insn_t& insn)
    {
        const int size = register_mapper::vector_reg_size(insn.Op1.reg);
        if (size <= 0)
            return;

        std::array<uint8_t, 32> lhs{};
        std::array<uint8_t, 32> rhs{};
        resolve_operands_2_or_3(uc, insn, lhs.data(), rhs.data(), size);

        std::array<uint8_t, 32> res{};
        for (int i = 0; i < size; ++i)
            res[i] = lhs[i] | rhs[i];

        write_operand(uc, insn.Op1, res.data(), size);
    }

    void handle_andn(uc_engine* uc, const insn_t& insn)
    {
        const int size = register_mapper::vector_reg_size(insn.Op1.reg);
        if (size <= 0)
            return;

        std::array<uint8_t, 32> lhs{};
        std::array<uint8_t, 32> rhs{};
        resolve_operands_2_or_3(uc, insn, lhs.data(), rhs.data(), size);

        std::array<uint8_t, 32> res{};
        for (int i = 0; i < size; ++i)
            res[i] = (~lhs[i]) & rhs[i];

        write_operand(uc, insn.Op1, res.data(), size);
    }

    template <typename T> void perform_add(uint8_t* res, const uint8_t* lhs, const uint8_t* rhs, int size)
    {
        const int count = size / sizeof(T);
        const T* l = reinterpret_cast<const T*>(lhs);
        const T* r = reinterpret_cast<const T*>(rhs);
        T* dst = reinterpret_cast<T*>(res);
        for (int i = 0; i < count; ++i)
            dst[i] = l[i] + r[i];
    }

    template <typename T> void perform_sub(uint8_t* res, const uint8_t* lhs, const uint8_t* rhs, int size)
    {
        const int count = size / sizeof(T);
        const T* l = reinterpret_cast<const T*>(lhs);
        const T* r = reinterpret_cast<const T*>(rhs);
        T* dst = reinterpret_cast<T*>(res);
        for (int i = 0; i < count; ++i)
            dst[i] = l[i] - r[i];
    }

    template <typename T> void perform_mull(uint8_t* res, const uint8_t* lhs, const uint8_t* rhs, int size)
    {
        const int count = size / sizeof(T);
        const T* l = reinterpret_cast<const T*>(lhs);
        const T* r = reinterpret_cast<const T*>(rhs);
        T* dst = reinterpret_cast<T*>(res);
        for (int i = 0; i < count; ++i)
            dst[i] = l[i] * r[i];
    }

    void handle_arithmetic(uc_engine* uc, const insn_t& insn)
    {
        const int size = register_mapper::vector_reg_size(insn.Op1.reg);
        if (size <= 0)
            return;

        std::array<uint8_t, 32> lhs{};
        std::array<uint8_t, 32> rhs{};
        resolve_operands_2_or_3(uc, insn, lhs.data(), rhs.data(), size);

        std::array<uint8_t, 32> res{};
        switch (insn.itype)
        {
        case NN_paddb:
        case NN_vpaddb:
            perform_add<uint8_t>(res.data(), lhs.data(), rhs.data(), size);
            break;
        case NN_psubb:
        case NN_vpsubb:
            perform_sub<uint8_t>(res.data(), lhs.data(), rhs.data(), size);
            break;
        case NN_paddw:
        case NN_vpaddw:
            perform_add<uint16_t>(res.data(), lhs.data(), rhs.data(), size);
            break;
        case NN_psubw:
        case NN_vpsubw:
            perform_sub<uint16_t>(res.data(), lhs.data(), rhs.data(), size);
            break;
        case NN_paddd:
        case NN_vpaddd:
            perform_add<uint32_t>(res.data(), lhs.data(), rhs.data(), size);
            break;
        case NN_psubd:
        case NN_vpsubd:
            perform_sub<uint32_t>(res.data(), lhs.data(), rhs.data(), size);
            break;
        case NN_paddq:
        case NN_vpaddq:
            perform_add<uint64_t>(res.data(), lhs.data(), rhs.data(), size);
            break;
        case NN_psubq:
        case NN_vpsubq:
            perform_sub<uint64_t>(res.data(), lhs.data(), rhs.data(), size);
            break;
        case NN_pmullw:
        case NN_vpmullw:
            perform_mull<int16_t>(res.data(), lhs.data(), rhs.data(), size);
            break;
        default:
            return;
        }

        write_operand(uc, insn.Op1, res.data(), size);
    }

    uint64_t resolve_shift_count(uc_engine* uc, const op_t& op)
    {
        if (op.type == o_imm)
            return op.value;

        uint64_t count = 0;
        read_operand(uc, op, reinterpret_cast<uint8_t*>(&count), 8);
        return count;
    }

    template <typename T, typename U>
    void perform_shift(uint8_t* res, const uint8_t* src, uint64_t count, int size, int itype)
    {
        const int count_elements = size / sizeof(T);
        const T* s = reinterpret_cast<const T*>(src);
        T* dst = reinterpret_cast<T*>(res);

        const int max_bits = sizeof(T) * 8;
        const bool is_left = (itype == NN_psllw || itype == NN_vpsllw ||
                              itype == NN_pslld || itype == NN_vpslld ||
                              itype == NN_psllq || itype == NN_vpsllq);
        const bool is_logical_right = (itype == NN_psrlw || itype == NN_vpsrlw ||
                                       itype == NN_psrld || itype == NN_vpsrld ||
                                       itype == NN_psrlq || itype == NN_vpsrlq);

        for (int i = 0; i < count_elements; ++i)
        {
            if (count >= static_cast<uint64_t>(max_bits))
            {
                if (is_left || is_logical_right)
                    dst[i] = 0;
                else
                    dst[i] = (s[i] < 0) ? -1 : 0;
            }
            else
            {
                if (is_left)
                    dst[i] = static_cast<T>(static_cast<U>(s[i]) << count);
                else if (is_logical_right)
                    dst[i] = static_cast<T>(static_cast<U>(s[i]) >> count);
                else
                    dst[i] = s[i] >> count;
            }
        }
    }

    void handle_shift(uc_engine* uc, const insn_t& insn)
    {
        const int size = register_mapper::vector_reg_size(insn.Op1.reg);
        if (size <= 0)
            return;

        std::array<uint8_t, 32> src{};
        uint64_t count = 0;

        if (insn.Op3.type != o_void)
        {
            read_operand(uc, insn.Op2, src.data(), size);
            count = resolve_shift_count(uc, insn.Op3);
        }
        else
        {
            read_operand(uc, insn.Op1, src.data(), size);
            count = resolve_shift_count(uc, insn.Op2);
        }

        std::array<uint8_t, 32> res{};
        switch (insn.itype)
        {
        case NN_psllw:
        case NN_vpsllw:
        case NN_psrlw:
        case NN_vpsrlw:
        case NN_psraw:
        case NN_vpsraw:
            perform_shift<int16_t, uint16_t>(res.data(), src.data(), count, size, insn.itype);
            break;

        case NN_pslld:
        case NN_vpslld:
        case NN_psrld:
        case NN_vpsrld:
        case NN_psrad:
        case NN_vpsrad:
            perform_shift<int32_t, uint32_t>(res.data(), src.data(), count, size, insn.itype);
            break;

        case NN_psllq:
        case NN_vpsllq:
        case NN_psrlq:
        case NN_vpsrlq:
            perform_shift<int64_t, uint64_t>(res.data(), src.data(), count, size, insn.itype);
            break;

        default:
            return;
        }

        write_operand(uc, insn.Op1, res.data(), size);
    }

    void perform_pshufb_16(uint8_t* dst, const uint8_t* src, const uint8_t* mask)
    {
        for (int i = 0; i < 16; ++i)
        {
            if (mask[i] & 0x80)
                dst[i] = 0;
            else
                dst[i] = src[mask[i] & 0x0F];
        }
    }

    void handle_pshufb(uc_engine* uc, const insn_t& insn)
    {
        const int size = register_mapper::vector_reg_size(insn.Op1.reg);
        if (size <= 0)
            return;

        std::array<uint8_t, 32> src{};
        std::array<uint8_t, 32> mask{};
        resolve_operands_2_or_3(uc, insn, src.data(), mask.data(), size);

        std::array<uint8_t, 32> res{};
        perform_pshufb_16(res.data(), src.data(), mask.data());
        if (size == 32)
            perform_pshufb_16(res.data() + 16, src.data() + 16, mask.data() + 16);

        write_operand(uc, insn.Op1, res.data(), size);
    }

    void handle_aes(uc_engine* uc, const insn_t& insn)
    {
        std::array<uint8_t, 16> state{};
        std::array<uint8_t, 16> key{};

        const bool is_avx = (insn.itype == NN_vaesenc || insn.itype == NN_vaesenclast ||
                             insn.itype == NN_vaesdec || insn.itype == NN_vaesdeclast ||
                             insn.itype == NN_vaesimc || insn.itype == NN_vaeskeygenassist);

        int itype = insn.itype;
        if (itype == NN_vaesenc) itype = NN_aesenc;
        else if (itype == NN_vaesenclast) itype = NN_aesenclast;
        else if (itype == NN_vaesdec) itype = NN_aesdec;
        else if (itype == NN_vaesdeclast) itype = NN_aesdeclast;
        else if (itype == NN_vaesimc) itype = NN_aesimc;
        else if (itype == NN_vaeskeygenassist) itype = NN_aeskeygenassist;

        if (itype == NN_aesenc || itype == NN_aesenclast || itype == NN_aesdec || itype == NN_aesdeclast)
        {
            if (is_avx)
            {
                read_operand(uc, insn.Op2, state.data(), 16);
                read_operand(uc, insn.Op3, key.data(), 16);
            }
            else
            {
                read_operand(uc, insn.Op1, state.data(), 16);
                read_operand(uc, insn.Op2, key.data(), 16);
            }

            if (itype == NN_aesenc)
                aes_impl::aesenc(state.data(), key.data());
            else if (itype == NN_aesenclast)
                aes_impl::aesenclast(state.data(), key.data());
            else if (itype == NN_aesdec)
                aes_impl::aesdec(state.data(), key.data());
            else if (itype == NN_aesdeclast)
                aes_impl::aesdeclast(state.data(), key.data());

            write_operand(uc, insn.Op1, state.data(), 16);
        }
        else if (itype == NN_aesimc)
        {
            read_operand(uc, insn.Op2, key.data(), 16);
            aes_impl::aesimc(state.data(), key.data());
            write_operand(uc, insn.Op1, state.data(), 16);
        }
        else if (itype == NN_aeskeygenassist)
        {
            read_operand(uc, insn.Op2, key.data(), 16);
            const uint8_t rcon = static_cast<uint8_t>(insn.Op3.value);
            aes_impl::aeskeygenassist(state.data(), key.data(), rcon);
            write_operand(uc, insn.Op1, state.data(), 16);
        }
    }

    void handle_vzeroupper(uc_engine* uc)
    {
        std::array<uint8_t, 32> ymm{};
        for (int i = 0; i < 16; ++i)
        {
            const int reg = UC_X86_REG_YMM0 + i;
            if (uc_reg_read(uc, reg, ymm.data()) != UC_ERR_OK)
                continue;

            std::fill(ymm.begin() + 16, ymm.end(), 0);
            uc_reg_write(uc, reg, ymm.data());
        }
    }
}

void handler::handle(uc_engine* uc, const uint64_t address, const uint32_t size, const insn_t& insn)
{
    vector_operations::update_rip(uc, address, size);
    logger::debug("custom handling at {0:x} with size {1:d}...", address, size);

    switch (insn.itype)
    {
    case NN_movdqa:
    case NN_movdqu:
    case NN_vmovdqa:
    case NN_vmovdqu:
    case NN_movaps:
    case NN_vmovaps:
    case NN_movups:
    case NN_vmovups:
    case NN_movapd:
    case NN_vmovapd:
    case NN_movupd:
    case NN_vmovupd:
    case NN_movd:
    case NN_vmovd:
    case NN_movq:
    case NN_vmovq:
        handle_move(uc, insn);
        break;

    case NN_pxor:
    case NN_vpxor:
        handle_xor(uc, insn);
        break;

    case NN_pand:
    case NN_vpand:
        handle_and(uc, insn);
        break;

    case NN_por:
    case NN_vpor:
        handle_or(uc, insn);
        break;

    case NN_pandn:
    case NN_vpandn:
        handle_andn(uc, insn);
        break;

    case NN_paddb:
    case NN_vpaddb:
    case NN_psubb:
    case NN_vpsubb:
    case NN_paddw:
    case NN_vpaddw:
    case NN_psubw:
    case NN_vpsubw:
    case NN_paddd:
    case NN_vpaddd:
    case NN_psubd:
    case NN_vpsubd:
    case NN_paddq:
    case NN_vpaddq:
    case NN_psubq:
    case NN_vpsubq:
    case NN_pmullw:
    case NN_vpmullw:
        handle_arithmetic(uc, insn);
        break;

    case NN_psllw:
    case NN_vpsllw:
    case NN_pslld:
    case NN_vpslld:
    case NN_psllq:
    case NN_vpsllq:
    case NN_psrlw:
    case NN_vpsrlw:
    case NN_psrld:
    case NN_vpsrld:
    case NN_psrlq:
    case NN_vpsrlq:
    case NN_psraw:
    case NN_vpsraw:
    case NN_psrad:
    case NN_vpsrad:
        handle_shift(uc, insn);
        break;

    case NN_pshufb:
    case NN_vpshufb:
        handle_pshufb(uc, insn);
        break;

    case NN_aesenc:
    case NN_aesenclast:
    case NN_aesdec:
    case NN_aesdeclast:
    case NN_aesimc:
    case NN_aeskeygenassist:
    case NN_vaesenc:
    case NN_vaesenclast:
    case NN_vaesdec:
    case NN_vaesdeclast:
    case NN_vaesimc:
    case NN_vaeskeygenassist:
        handle_aes(uc, insn);
        break;

    case NN_vzeroupper:
        handle_vzeroupper(uc);
        break;

    default:
        break;
    }
}
