/*
cencode.h - c header for a base64 encoding algorithm

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

#ifndef BASE64_CENCODE_H
#define BASE64_CENCODE_H

/*
 * Declarations
 */

typedef enum
{
    step_A,
    step_B,
    step_C
} base64_encodestep;

typedef struct
{
    base64_encodestep step;
    char result;
    int stepcount;
} base64_encodestate;

void base64_init_encodestate( base64_encodestate* state_in );

char base64_encode_value( char value_in );

int base64_encode_block( const char* plaintext_in, 
                         int length_in,
                         char* code_out,
                         base64_encodestate* state_in );

int base64_encode_blockend( char* code_out,
                            base64_encodestate* state_in );

/*
 * Definitions
 */ 

/* const int CHARS_PER_LINE = 72; */

void base64_init_encodestate( base64_encodestate* state_in ) {
    state_in->step = step_A;
    state_in->result = 0;
/*	state_in->stepcount = 0; */
}

char base64_encode_value( char value_in ) {
    static const char encoding[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char encoding_size = sizeof(encoding);
    if (value_in >= encoding_size) {
        return '=';
    }
    return encoding[(int)value_in];
}

int base64_encode_block( const char* plaintext_in,
                         int length_in,
                         char* code_out,
                         base64_encodestate* state_in ) {
    const char* plainchar = plaintext_in;
    const char* const plaintextend = plaintext_in + length_in;
    char* codechar = code_out;
    char result;
    char fragment;
    
    result = state_in->result;
    
    switch (state_in->step)
    {
        while (1)
        {
    case step_A:
            if (plainchar == plaintextend)
            {
                state_in->result = result;
                state_in->step = step_A;
                return codechar - code_out;
            }
            fragment = *plainchar++;
            result = (fragment & 0x0fc) >> 2;
            *codechar++ = base64_encode_value(result);
            result = (fragment & 0x003) << 4;
    case step_B:
            if (plainchar == plaintextend)
            {
                state_in->result = result;
                state_in->step = step_B;
                return codechar - code_out;
            }
            fragment = *plainchar++;
            result |= (fragment & 0x0f0) >> 4;
            *codechar++ = base64_encode_value(result);
            result = (fragment & 0x00f) << 2;
    case step_C:
            if (plainchar == plaintextend)
            {
                state_in->result = result;
                state_in->step = step_C;
                return codechar - code_out;
            }
            fragment = *plainchar++;
            result |= (fragment & 0x0c0) >> 6;
            *codechar++ = base64_encode_value(result);
            result  = (fragment & 0x03f) >> 0;
            *codechar++ = base64_encode_value(result);
        }
    }
    /* control should not reach here */
    return codechar - code_out;
}

int base64_encode_blockend( char* code_out,
                            base64_encodestate* state_in ) {
    char* codechar = code_out;
    
    switch (state_in->step)
    {
    case step_B:
        *codechar++ = base64_encode_value(state_in->result);
        *codechar++ = '=';
        *codechar++ = '=';
        break;
    case step_C:
        *codechar++ = base64_encode_value(state_in->result);
        *codechar++ = '=';
        break;
    case step_A:
        break;
    }
/*	*codechar++ = '\n'; */
    
    return codechar - code_out;
}

#endif /* BASE64_CENCODE_H */
