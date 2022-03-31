// Copyright (c) 2022 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once
#include "error.hpp"
#include "fd.hpp"

extern "C" {
#include <bpf.h>
#include <libbpf.h>
}

#include <cstdint>
#include <utility>


namespace Bpf {

class Map
{
public:
    Map(int fd, std::uint32_t type);

    virtual ~Map() = default;

    /// \brief Returns the map's file descriptor.
    virtual int getFd() const = 0;

    /// \brief Search for en element in the map and return its value in \p value .
    /// \param[in] key
    /// \param[in] keySize Length of \p key in bytes.
    /// \param[out] value
    /// \param[in] valueSize Length of \p value in bytes.
    /// \return True if the element was found, otherwise false.
    bool lookup(
        const void *key, std::uint32_t keySize,
        void *value, std::uint32_t valueSize) const;

    /// \brief Search for en element in the map, delete it and return its former value in \p value .
    /// \param[in] key
    /// \param[in] keySize Length of \p key in bytes.
    /// \param[out] value
    /// \param[in] valueSize Length of \p value in bytes.
    /// \return True if the element was found, otherwise false.
    bool lookupAndErase(
        const void *key, std::uint32_t keySize,
        void *value, std::uint32_t valueSize) const;

    /// \brief Create or update an element in the map.
    /// \param[in] key
    /// \param[in] keySize Length of \p key in bytes.
    /// \param[in] value
    /// \param[in] valueSize Length of \p value in bytes.
    /// \param[in] flags One of `BPF_ANY`, `BPF_NOEXIST`, `BPF_EXIST`.
    /// \return True if the update was successful, otherwise false.
    bool update(
        const void *key, std::uint32_t keySize,
        const void *value, std::uint32_t valueSize,
        std::uint64_t flags) const;

    /// \brief Erase an element from the map.
    /// \param[in] key
    /// \param[in] keySize Length of \p key in bytes.
    /// \return True if the element was removed, false if the key was not found.
    bool erase(const void *key, std::uint32_t keySize);

private:
    bool verifyArgSize(std::uint32_t key, std::uint32_t value) const;

private:
    std::uint32_t mapType, keySize, valueSize;
};

class BpfLibMap : public Map
{
public:
    BpfLibMap(struct bpf_map* map, std::uint32_t type);

    int getFd() const override
    { return bpf_map__fd(map); }

    const char* getPinPath() const { return bpf_map__get_pin_path(map); }
    void setPinPath(const char* path) { bpf_map__set_pin_path(map, path); }

    void pin(const char* path)
    {
        int err = bpf_map__pin(map, path);
        if (err) throw BpfError(-err, "Pinning map failed");
    }

    void unpin(const char* path)
    {
        int err = bpf_map__unpin(map, path);
        if (err) throw BpfError(-err, "Unpinning map failed");
    }

private:
    BpfLibMap(struct bpf_map* map, int fd, std::uint32_t type);
    friend class Object;

private:
    struct bpf_map *map = nullptr;
};

class PinnedMap : public Map
{
public:
    static PinnedMap Open(const char* path, std::uint32_t type);

    int getFd() const override { return fd.get(); }

private:
    PinnedMap(FileDesc fd, std::uint32_t type)
        : Map(fd.get(), type), fd(std::move(fd))
    {}

private:
    FileDesc fd;
};

} // namespac Bpf
