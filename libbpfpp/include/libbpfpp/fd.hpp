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

extern "C" {
#include <unistd.h>
}

#include <utility>


namespace Bpf {

/// \brief RAII wrapper for file descriptors.
class FileDesc
{
public:
    FileDesc() = default;
    FileDesc(int fd) : fd(fd) {}

    FileDesc(const FileDesc &other) = delete;
    FileDesc(FileDesc &&other) noexcept
        : fd(std::exchange(other.fd, -1))
    {}

    FileDesc& operator=(const FileDesc &other) = delete;
    FileDesc& operator=(FileDesc &&other) noexcept
    {
        std::swap(fd, other.fd);
        return *this;
    }

    ~FileDesc()
    {
        if (fd >= 0) close(fd);
    }

    operator bool() const { return fd >= 0; }

    int get() const { return fd; }
    int release() { return std::exchange(fd, -1); }

private:
    int fd = -1;
};

} // namespace Bpf
