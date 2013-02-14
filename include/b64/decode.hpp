// :mode=c++:
/*
decode.h - c++ wrapper for a base64 decoding algorithm

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
#ifndef BASE64_DECODE_H
#define BASE64_DECODE_H

#include <iostream>

namespace base64
{
    extern "C"
    {
        #include "cdecode.h"
    }

    struct decoder
    {
        base64_decodestate _state;
        int _buffersize;

        decoder(int buffersize_in = BUFFERSIZE)
        : _buffersize(buffersize_in)
        {}

        int decode(char value_in)
        {
            return base64_decode_value(value_in);
        }

        int decode(const char* code_in, const int length_in, char* plaintext_out)
        {
            return base64_decode_block(code_in, length_in, plaintext_out, &_state);
        }

        void decode(std::istream& istream_in, std::ostream& ostream_in)
        {
            base64_init_decodestate(&_state);
            //
            const int N = _buffersize;
            char* code = new char[N];
            char* plaintext = new char[N];
            int codelength;
            int plainlength;

            do
            {
                istream_in.read((char*)code, N);
                codelength = istream_in.gcount();
                if( (plainlength = decode(code, codelength, plaintext)) < 0 ) {
                    std::cerr << "Breaking because of invalid encoded characters." << std::endl;
                    break;
                }
                ostream_in.write((const char*)plaintext, plainlength);
            }
            while (istream_in.good() && codelength > 0);
            //
            base64_init_decodestate(&_state);

            delete [] code;
            delete [] plaintext;
        }
    };

} // namespace base64



#endif // BASE64_DECODE_H

