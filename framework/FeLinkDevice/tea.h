#ifndef _FELINK_DEV_TEA_
#define _FELINK_DEV_TEA_

#include "felink.h"

flresult fl_xxtea_encrypt(flu32 *plaintext, fluint dword_len, flu32 *key);
flresult fl_xxtea_decrypt(flu32 *ciphetext, fluint dword_len, flu32 *key);
flresult fl_xxtea_byte_array_encrypt(flu8 *plaintext, fluint byte_len, flu32 *key);
flresult fl_xxtea_byte_array_decrypt(flu8 *ciphetext, fluint byte_len, flu32 *key);

#endif // !_FELINK_DEV_TEA_
