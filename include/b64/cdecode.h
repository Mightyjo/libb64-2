/*
cdecode.h - c header for a base64 decoding algorithm

Copyright 2012 Joseph R. Langley

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

#ifndef BASE64_CDECODE_H
#define BASE64_CDECODE_H

/* 
 * Declarations 
 */

typedef enum
{
    step_a,
    step_b,
    step_c,
    step_d
} base64_decodestep;

typedef struct
{
    base64_decodestep step;
    char plainchar;
} base64_decodestate;

void base64_init_decodestate( base64_decodestate* state_in );

int base64_decode_value( char value_in );

int base64_decode_block( const char* code_in, 
                         const int length_in,
                         char* plaintext_out,
                         base64_decodestate* state_in );

/*
 * Definitions
 */
 
int base64_decode_value( char value_in ) {
    /*
     * Some beautiful magic is happening here.  We're trying to decode
     * characters from ASCII encoding into binary according to an en-
     * coding sequence that didn't translate linearly from binary to 
     * ASCII code points.  Fun, huh?
     *
     * Here's what you're seeing:
     * The incoming value gets reduced by 43.  Why?  Because that's the 
     * ASCII code point for '+', the smallest-valued character in the
     * Base64 endcoding table.  The decoding matrix below contains the
     * decimal values for all the code points between ASCII '+' and 'z'.
     * Those that aren't valid Base64 characters return -1 so we can
     * detect the input error in the base64_decode_block() function.
     */
    static const char decoding[] = {
        62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,
        61,-1,-1,-1,-2,-1,-1,-1, 0, 1, 2, 3, 4, 5,
         6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,
        20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,
        28,29,30,31,32,33,34,35,36,37,38,39,40,41,
        42,43,44,45,46,47,48,49,50,51
    };
    static const char decoding_size = sizeof(decoding);
    value_in -= 43; /* ASCII '+' == 43 */
    if (value_in < 0 || value_in > decoding_size) {
        return -1; /* This handles any input less than '+' or greater */
                   /* than 'z'.                                       */
    }
    return decoding[(int)value_in];
}

void base64_init_decodestate( base64_decodestate* state_in ) {
    state_in->step = step_a;
    state_in->plainchar = 0;
    return;
}

int base64_decode_block( const char* code_in,
                         const int length_in,
                         char* plaintext_out,
                         base64_decodestate* state_in ) {

    const char* codechar = code_in;
    char* plainchar = plaintext_out;
    char fragment;
    
    *plainchar = state_in->plainchar;
    
    switch (state_in->step)
    {
        while (1)
        {
    case step_a:
            do {
                if (codechar == code_in+length_in)
                {
                    state_in->step = step_a;
                    state_in->plainchar = *plainchar;
                    return plainchar - plaintext_out;
                }
                fragment = (char)base64_decode_value(*codechar++);
                if( fragment == -1 ) goto error;
            } while( fragment < -1 );
            *plainchar    = (fragment & 0x03f) << 2;
    case step_b:
            do {
                if (codechar == code_in+length_in)
                {
                    state_in->step = step_b;
                    state_in->plainchar = *plainchar;
                    return plainchar - plaintext_out;
                }
                fragment = (char)base64_decode_value(*codechar++);
                if( fragment == -1 ) goto error;
            } while( fragment < -1 );
            *plainchar++ |= (fragment & 0x030) >> 4;
            *plainchar    = (fragment & 0x00f) << 4;
    case step_c:
            do {
                if (codechar == code_in+length_in)
                {
                    state_in->step = step_c;
                    state_in->plainchar = *plainchar;
                    return plainchar - plaintext_out;
                }
                fragment = (char)base64_decode_value(*codechar++);
                if( fragment == -1 ) goto error;
            } while( fragment < -1 );
            *plainchar++ |= (fragment & 0x03c) >> 2;
            *plainchar    = (fragment & 0x003) << 6;
    case step_d:
            do {
                if (codechar == code_in+length_in)
                {
                    state_in->step = step_d;
                    state_in->plainchar = *plainchar;
                    return plainchar - plaintext_out;
                }
                fragment = (char)base64_decode_value(*codechar++);
                if( fragment == -1 ) goto error;
            } while( fragment < -1 );
            *plainchar++   |= (fragment & 0x03f);
        }
error:
        /* control comes here when invalid characters occur in the data. */
        return -1;
    }
    /* control should not reach here */
    return plainchar - plaintext_out;

}

#endif /* BASE64_CDECODE_H */
