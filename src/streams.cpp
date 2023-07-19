// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <span.h>
#include <streams.h>

#include <array>

std::size_t AutoFile::detail_fread(Span<std::byte> dst)
{
    if (!m_file) throw std::ios_base::failure("AutoFile::read: file handle is nullptr");
    if (m_xor.empty()) {
        return std::fread(dst.data(), 1, dst.size(), m_file);
    }
    std::size_t ret{std::fread(dst.data(), 1, dst.size(), m_file)};
    util::Xor(dst.subspan(0, ret), m_xor, m_xorfilepos);
    m_xorfilepos += ret;
    return ret;
}

void AutoFile::read(Span<std::byte> dst)
{
    if (detail_fread(dst) != dst.size()) {
        throw std::ios_base::failure(feof() ? "AutoFile::read: end of file" : "AutoFile::read: fread failed");
    }
}

void AutoFile::ignore(size_t nSize)
{
    if (!m_file) throw std::ios_base::failure("AutoFile::ignore: file handle is nullptr");
    unsigned char data[4096];
    while (nSize > 0) {
        size_t nNow = std::min<size_t>(nSize, sizeof(data));
        auto numBytes = std::fread(data, 1, nNow, m_file);
        if (!m_xor.empty()) m_xorfilepos += numBytes;
        if (numBytes != nNow) {
            throw std::ios_base::failure(feof() ? "AutoFile::ignore: end of file" : "AutoFile::ignore: fread failed");
        }
        nSize -= nNow;
    }
}

void AutoFile::write(Span<const std::byte> src)
{
    if (!m_file) throw std::ios_base::failure("AutoFile::write: file handle is nullptr");
    if (m_xor.empty()) {
        if (std::fwrite(src.data(), 1, src.size(), m_file) != src.size()) {
            throw std::ios_base::failure("AutoFile::write: write failed");
        }
    } else {
        std::array<std::byte, 4096> buf;
        while (src.size() > 0) {
            auto buf_now{Span{buf}.first(std::min<size_t>(src.size(), buf.size()))};
            std::copy(src.begin(), src.begin() + buf_now.size(), buf_now.begin());
            util::Xor(buf_now, m_xor, m_xorfilepos);
            auto numBytes = std::fwrite(buf_now.data(), 1, buf_now.size(), m_file);
            m_xorfilepos += numBytes;
            if (numBytes != buf_now.size()) {
                throw std::ios_base::failure{"XorFile::write: failed"};
            }
            src = src.subspan(buf_now.size());
        }
    }
}
