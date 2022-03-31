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

#include "libbpfpp/error.hpp"

#include <string.h>


namespace Bpf {

BpfError::BpfError(int code, const std::string& message)
    : code(code)
{
    std::stringstream stream;
    stream << "BPF Error: " << message << " (" << strerror(code) << ")";
    this->message = stream.str();
}

XdpAttachError::XdpAttachError(int code, int ifindex, const std::string& message)
{
    this->code = code;
    this->ifindex = ifindex;

    std::stringstream stream;
    stream << "XDP Attachment Error: " << message << " (IF: " << ifindex << ")";
    this->message = stream.str();
}

} // namespace Bpf
