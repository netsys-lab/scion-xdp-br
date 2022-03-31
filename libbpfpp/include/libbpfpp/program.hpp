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
#include "map.hpp"

extern "C" {
#include <libbpf.h>
}

#include <cstdint>
#include <optional>
#include <filesystem>


namespace Bpf {

class Program
{
public:
    Program(struct bpf_program* prog) : prog(prog)
    {}

    /// \brief Get the file descriptor of the program.
    int getFd() const
    { return bpf_program__fd(prog); }

    /// \brief Set the BPF program type.
    /// \details libbpf tries to auto-detect the correct program type. This function allows to
    /// override the auto-detection algorithm, or provide the progam type in case auto-detection
    /// fails. Must be called before attempting to lead the program in the kernel.
    void setType(bpf_prog_type type)
    { bpf_program__set_type(prog, type); }

    void setExpectedAttachType(bpf_attach_type type)
    { bpf_program__set_expected_attach_type(prog, type); }

    /// \brief Set the index of the network interface the program is supposed to be attached to.
    /// \details The IF index must be known at load time, if hardware offload is desired, otherwise
    /// it is not necessary to set it using this function.
    void setIfIndex(unsigned int ifindex)
    { bpf_program__set_ifindex(prog, ifindex); }

    /// \brief Attach the program to the XDP hook of a network interface.
    /// \param[in] ifindex
    /// \param[in] flags A combination of XDP_FLAGS_*
    void attachXDP(int ifindex, std::uint32_t flags)
    {
        int err = bpf_set_link_xdp_fd(ifindex, bpf_program__fd(prog), flags);
        switch (-err)
        {
        case 0:
            return;
        case EBUSY:
        case EEXIST:
            throw BpfError(-err, "Another program is already attached");
        case EOPNOTSUPP:
            throw BpfError(-err, "XDP attachment mode not supported");
        default:
            throw BpfError(-err, strerror(-err));
        }
    }

    /// \brief Remove the currently attached XDP program from a network interface.
    /// \param[in] ifindex
    /// \param[in] flags A combination of XDP_FLAGS_*
    static void detachXDP(int ifindex, std::uint32_t flags)
    {
        int err = bpf_set_link_xdp_fd(ifindex, -1, flags);
        if (err) throw XdpAttachError(-err, ifindex, "Detaching XDP program failed");
    }

    void pin(const char* path)
    {
        int err = bpf_program__pin(prog, path);
        if (err) throw BpfError(err, "Pinning program failed");
    }

    void unpin(const char* path)
    {
        int err = bpf_program__unpin(prog, path);
        if (err) throw BpfError(err, "Unpinning program failed");
    }

private:
    struct bpf_program *prog = nullptr;
};

class Object
{
public:
    /// \brief Load an ELF file into memory.
    static Object FromFile(const std::filesystem::path &objFile)
    {
        auto obj = bpf_object__open(objFile.c_str());
        int err = -libbpf_get_error(obj);
        if (err) throw BpfError(err, "Error reading " + objFile.string());
        return Object(obj);
    }

    Object(const Object &other) = delete;
    Object(Object &&other) noexcept
        : obj(other.obj)
    {}

    Object& operator=(const Object &other) = delete;
    Object& operator=(Object &&other) noexcept
    {
        if (&other != this)
            obj = std::exchange(other.obj, nullptr);
        return *this;
    }

    ~Object()
    {
        if (obj) bpf_object__close(obj);
    }

    /// \brief Load all programs contained in the object into the kernel.
    void load()
    {
        int err = bpf_object__load(obj);
        if (err) throw BpfError(err, "Loading OBJ failed");
    }

    /// \brief Pin all maps declared in the object.
    void pinMaps(const char* path)
    {
        int err = bpf_object__pin_maps(obj, path);
        if (err) throw BpfError(-err, "Pinning maps failed");
    }

    /// \brief Unpin all maps declared in the object.
    void unpinMaps(const char* path)
    {
        int err = bpf_object__unpin_maps(obj, path);
        if (err) throw BpfError(-err, "Unpinning maps failed");
    }

    /// \brief Reuse a map that was previously pinned.
    /// \param[in] name Name of the map as defined in the object file.
    /// \param[in] path Path of the pinned map.
    /// \return True if the map is reused.
    bool reusePinnedMap(const char* name, const char* path)
    {
        // Find the map
        auto ptr = bpf_object__find_map_by_name(obj, name);
        if (!ptr)
        {
            int err = -libbpf_get_error(ptr);
            if (err == ENOENT) return false;
            if (err) throw BpfError(err, "Error in bpf_object__find_map_by_name");
        }

        // Open the pinned map
        int fd = bpf_obj_get(path);
        if (fd >= 0)
        {
            int err = bpf_map__reuse_fd(ptr, fd);
            if (err) throw BpfError(-err, "Error in bpf_map__reuse_fd");
            return true;
        }
        return false;
    }

    /// \brief Search for a program by ELF section name.
    std::optional<Program> findProgramBySection(const char* section) const
    {
        auto ptr = bpf_object__find_program_by_title(obj, section);
        if (ptr)
        {
            int err = -libbpf_get_error(ptr);
            if (err) throw BpfError(err, "Error in bpf_object__find_program_by_title");
            return Program(ptr);
        }
        return std::nullopt;
    }

    /// \brief Search for a map by name.
    /// \param[in] name Name of the map
    /// \param[in] type Expected map type (One of BPF_MAP_TYPE_*)
    std::optional<BpfLibMap> findMapByName(
        const char* name, std::uint32_t type) const
    {
        auto ptr = bpf_object__find_map_by_name(obj, name);
        if (ptr)
        {
            int err = -libbpf_get_error(ptr);
            if (err == ENOENT) return std::nullopt;
            else if (err) throw BpfError(err, "Error in bpf_object__find_map_by_name");
            return BpfLibMap(ptr, type);
        }
        return std::nullopt;
    }

    /// \brief Execute \p func for every program contained in the object.
    /// \param[in] func A callable with the signature `void func(struct bpf_program*)`.
    template <typename F>
    void forEachProgram(F func)
    {
        struct bpf_program *prog = nullptr;
        bpf_object__for_each_program(prog, obj) {
            func(Program(prog));
        }
    }

private:
    Object(struct bpf_object *obj)
        : obj(obj)
    { }

private:
    struct bpf_object *obj = nullptr;
};

} // namespace Bpf
