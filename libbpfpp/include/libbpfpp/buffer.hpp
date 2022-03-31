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
#include <bpf.h>
#include <libbpf.h>
}

#include <cstdint>
#include <memory>


namespace Bpf {

class RingBuffer
{
public:
    RingBuffer(const Map &map, ring_buffer_sample_fn callback)
        : buffer(ring_buffer__new(map.getFd(), callback, nullptr, nullptr))
    {}

    void poll(int timeout)
    {
        ring_buffer__poll(buffer.get(), timeout);
    }

private:
    struct Deleter
    {
        void operator()(struct ring_buffer *buffer) const {
            ring_buffer__free(buffer);
        }
    };
    std::unique_ptr<struct ring_buffer, Deleter> buffer = nullptr;
};

} // namespace Bpf
