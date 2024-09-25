/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* Test Pointer Auttributes */

#include <string.h>
#include <sys/types.h>

#include "../Enclave.h"
#include "Enclave_t.h"
#include "sgx_lfence.h"
#include "sgx_trts.h"

#define MR_PAIRING_BLS    // AES-256 security
#define AES_SECURITY 256

#include "pairing_3.h"
#include "miracl.h"

int g_err = 0;
#define ASSERT(x) { if (!(x)) { printf("err %s:%d\n", __FILE__, __LINE__); g_err++; } }


int pairing_main()
{
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve

	G1 Alice,Bob,sA,sB;
    G2 B6,Server,sS;
	GT res,sp,ap,bp;
	Big ss, s,a,b;


	int iss = 100;
    // pfc.random(ss);    // TA's super-secret 
	char ss_str[] = "ffffffffffffffffffffffffffffffffffffffffec3";
	flash ss_flash;
	cinstr(ss_flash, ss_str);
	ss = Big(ss_flash);


    printf("Mapping Server ID to point\n");
	pfc.hash_and_map(Server,(char *)"Server");

    printf("Mapping Alice & Bob ID's to points\n");
    pfc.hash_and_map(Alice,(char *)"Alice");
    pfc.hash_and_map(Bob,(char *)"Robert");

    printf("Alice, Bob and the Server visit Trusted Authority\n"); 

    sS=pfc.mult(Server,ss); 
	sA=pfc.mult(Alice,ss);
    sB=pfc.mult(Bob,ss); 

    printf("Alice and Server Key Exchange\n");

	
    // pfc.random(a);  // Alice's random number
    // pfc.random(s);   // Server's random number
    char a_str[] = "ffffffffffffffffffffffffffffffffffffffffec5";
	flash a_flash;
	cinstr(a_flash, a_str);
	a = Big(a_flash);

    char s_str[] = "ffffffffffffffffffffffffffffffffffffffffec7";
	flash s_flash;
	cinstr(s_flash, s_str);
	s = Big(s_flash);


	res=pfc.pairing(Server,sA);

	if (!pfc.member(res))
    {
        printf("Wrong group order - aborting\n");
        return 0;
    }
	
	ap=pfc.power(res,a);

	res=pfc.pairing(sS,Alice);
	
   	if (!pfc.member(res))
    {
        printf("Wrong group order - aborting\n");
        return 0;
    }

	sp=pfc.power(res,s);

    // printf("Alice  Key= %s\n", pfc.hash_to_aes_key(pfc.power(sp,a)));
    // printf("Server Key= %s\n",< pfc.hash_to_aes_key(pfc.power(ap,s)));

    printf("Bob and Server Key Exchange\n");

    pfc.random(b);   // Bob's random number
    pfc.random(s);   // Server's random number

	res=pfc.pairing(Server,sB);
    if (!pfc.member(res))
    {
        printf("Wrong group order - aborting\n");
        return 0;
    }
    bp=pfc.power(res,b);

	res=pfc.pairing(sS,Bob);
    if (!pfc.member(res))
    {
        printf("Wrong group order - aborting\n");
        return 0;
    }

    sp=pfc.power(res,s);

    // printf("Bob's  Key= %s\n", pfc.hash_to_aes_key(pfc.power(sp,b)));
    // printf("Server Key= %s\n", pfc.hash_to_aes_key(pfc.power(bp,s)));

    return 0;


}

#define MR_PAIRING_BN    // AES-128 or AES-192 security
int bls_main() {
{   
	PFC pfc(128);  // initialise pairing-friendly curve

	G2 Q,V;
	G1 S,R;
	int lsb;
	Big s,X;
	time_t seed;

	time(&seed);
    irand((long)seed);

// Create system-wide G2 constant
	pfc.random(Q);

	pfc.random(s);    // private key
	V=pfc.mult(Q,s);  // public key

// signature
	pfc.hash_and_map(R,(char *)"Test Message to sign");
	S=pfc.mult(R,s);

	lsb=S.g.get(X);   // signature is lsb bit and X

	cout << "Signature= " << lsb << " " << X << endl;

// verification	- first recover full point S
	if (!S.g.set(X,1-lsb))
	{
		cout << "Signature is invalid" << endl;
		exit(0);
	}
	pfc.hash_and_map(R,(char *)"Test Message to sign");


// Observe that Q is a constant
// Interesting that this optimization doesn't work for the Tate pairing, only the Ate

	pfc.precomp_for_pairing(Q);

	G1 *g1[2];
	G2 *g2[2];
	g1[0]=&S; g1[1]=&R;
	g2[0]=&Q; g2[1]=&V;

	if (pfc.multi_pairing(2,g2,g1)==1)
		cout << "Signature verifies" << endl;
	else
		cout << "Signature is bad" << endl;

    return 0;
}
}

/* checksum_internal:
 *   get simple checksum of input buffer and length
 */
int32_t checksum_internal(char* buf, size_t count)
{
    register int32_t sum = 0;
    int16_t* ptr = (int16_t*)buf;

    /* Main summing loop */
    while (count > 1) {
        sum = sum + *ptr++;
        count = count - 2;
    }

    /* Add left-over byte, if any */
    if (count > 0) {
        sum = sum + *((char*)ptr);
    }

    return ~sum;
}

/* ecall_pointer_user_check, ecall_pointer_in, ecall_pointer_out, ecall_pointer_in_out:
 *   The root ECALLs to test [in], [out], [user_check] attributes.
 */
size_t ecall_pointer_user_check(void* val, size_t sz)
{
    /* check if the buffer is allocated outside */
    if (sgx_is_outside_enclave(val, sz) != 1)
        abort();

    /*fence after sgx_is_outside_enclave check*/
    sgx_lfence();

    char tmp[100] = { 0 };
    size_t len = sz > 100 ? 100 : sz;

    /* copy the memory into the enclave to make sure 'val' 
     * is not being changed in checksum_internal() */
    memcpy(tmp, val, len);

    int32_t sum = checksum_internal((char*)tmp, len);
    printf("Checksum(0x%p, %zu) = 0x%x\n",
        val, len, (unsigned int)sum);

    /* modify outside memory directly */
    memcpy_verw(val, "SGX_SUCCESS", len > 12 ? 12 : len);

    pairing_main();

    return len;
}

/* ecall_pointer_in:
 *   the buffer of val is copied to the enclave.
 */

void ecall_pointer_in(int* val)
{
    if (sgx_is_within_enclave(val, sizeof(int)) != 1)
        abort();
    assert(*val == 1);
    *val = 1234;
}

/* ecall_pointer_out:
 *   the buffer of val is copied to the untrusted side.
 */
void ecall_pointer_out(int* val)
{
    if (sgx_is_within_enclave(val, sizeof(int)) != 1)
        abort();
    assert(*val == 0);
    *val = 1234;
}

/* ecall_pointer_in_out:
 * the buffer of val is double-copied.
 */
void ecall_pointer_in_out(int* val)
{
    if (sgx_is_within_enclave(val, sizeof(int)) != 1)
        abort();
    assert(*val == 1);
    *val = 1234;
}

/* ocall_pointer_attr:
 *   The root ECALL that test OCALL [in], [out], [user_check].
 */
void ocall_pointer_attr(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    int val = 0;
    ret = ocall_pointer_user_check(&val);
    if (ret != SGX_SUCCESS)
        abort();

    val = 0;
    ret = ocall_pointer_in(&val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 0);

    val = 0;
    ret = ocall_pointer_out(&val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 1234);

    val = 0;
    ret = ocall_pointer_in_out(&val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 1234);

    return;
}

/* ecall_pointer_string:
 *   [string] defines a string.
 */
void ecall_pointer_string(char* str)
{
    strncpy(str, "0987654321", strlen(str));
}

/* ecall_pointer_string_const:
 *   const [string] defines a string that cannot be modified.
 */
void ecall_pointer_string_const(const char* str)
{
    char* temp = new char[strlen(str)];
    strncpy(temp, str, strlen(str));
    delete[] temp;
}

/* ecall_pointer_size:
 *   'len' needs to be specified to tell Edger8r the length of 'str'.
 */
void ecall_pointer_size(void* ptr, size_t len)
{
    strncpy((char*)ptr, "0987654321", len);
}

/* ecall_pointer_count:
 *   'cnt' needs to be specified to tell Edger8r the number of elements in 'arr'.
 */
void ecall_pointer_count(int* arr, size_t count)
{
    int cnt = (int)count;
    for (int i = (cnt - 1); i >= 0; i--)
        arr[i] = (cnt - 1 - i);
}

/* ecall_pointer_isptr_readonly:
 *   'buf' is user defined type, shall be tagged with [isptr].
 *   if it's not writable, [readonly] shall be specified. 
 */
void ecall_pointer_isptr_readonly(buffer_t buf, size_t len)
{
    strncpy((char*)buf, "0987654321", len);
}
