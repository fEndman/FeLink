#ifndef _FELINK_DEV_TEA_
#define _FELINK_DEV_TEA_

#include "felink.h"

FLRESULT fl_xxtea_encrypt(FLU32 *plaintext, FLUINT dword_len, FLU32 *key);
FLRESULT fl_xxtea_decrypt(FLU32 *ciphetext, FLUINT dword_len, FLU32 *key);
FLRESULT fl_xxtea_byte_array_encrypt(FLU8 *plaintext, FLUINT byte_len, FLU32 *key);
FLRESULT fl_xxtea_byte_array_decrypt(FLU8 *ciphetext, FLUINT byte_len, FLU32 *key);

#endif // !_FELINK_DEV_TEA_
