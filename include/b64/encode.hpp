/*
encode.hpp - c++ wrapper for a base64 encoding algorithm

Copyright 2012 Joseph R. Langley
https://github.com/Mightyjo/libb64-2

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


Derived from the libb64 project written and dedicated to the public
domain by Chris Venter.
http://libb64.sourceforge.net/
 
*/
#ifndef BASE64_ENCODE_H
#define BASE64_ENCODE_H

#include <iostream>

namespace base64
{
    extern "C" 
    {
        #include "cencode.h"
    }

    struct encoder
    {
        base64_encodestate _state;
        int _buffersize;

        encoder(int buffersize_in = BUFFERSIZE)
        : _buffersize(buffersize_in)
        {}

        int encode(char value_in)
        {
            return base64_encode_value(value_in);
        }

        int encode(const char* code_in, const int length_in, char* plaintext_out)
        {
            return base64_encode_block(code_in, length_in, plaintext_out, &_state);
        }

        int encode_end(char* plaintext_out)
        {
            return base64_encode_blockend(plaintext_out, &_state);
        }

        void encode(std::istream& istream_in, std::ostream& ostream_in)
        {
            base64_init_encodestate(&_state);
            //
            const int N = _buffersize;
            char* plaintext = new char[N];
            char* code = new char[2*N];
            int plainlength;
            int codelength;

            do
            {
                istream_in.read(plaintext, N);
                plainlength = istream_in.gcount();
                //
                codelength = encode(plaintext, plainlength, code);
                ostream_in.write(code, codelength);
            }
            while (istream_in.good() && plainlength > 0);

            codelength = encode_end(code);
            ostream_in.write(code, codelength);
            //
            base64_init_encodestate(&_state);

            delete [] code;
            delete [] plaintext;
        }
    };

} // namespace base64

#endif // BASE64_ENCODE_H

