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
#include <mcl/bn_c384_256.h>

int g_err = 0;
#define ASSERT(x) { if (!(x)) { printf("err %s:%d\n", __FILE__, __LINE__); g_err++; } }


int pairing_main()
{
	// ecdsa_test();
	printf("OK0\n");
	char buf[1600];
	const char *aStr = "123";
	const char *bStr = "456";
	int ret = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (ret != 0) {
		printf("err ret=%d\n", ret);
		return 1;
	}
	printf("OK1\n");
	mclBnFr a, b, ab;
	mclBnG1 P, aP;
	mclBnG2 Q, bQ;
	mclBnGT e, e1, e2;
	printf("OK2\n");
	mclBnFr_setStr(&a, aStr, strlen(aStr), 10);
	mclBnFr_setStr(&b, bStr, strlen(bStr), 10);
	printf("OK3\n");
	mclBnFr_mul(&ab, &a, &b);
	mclBnFr_getStr(buf, sizeof(buf), &ab, 10);
	printf("%s x %s = %s\n", aStr, bStr, buf);
	mclBnFr_sub(&a, &a, &b);
	mclBnFr_getStr(buf, sizeof(buf), &a, 10);
	printf("%s - %s = %s\n", aStr, bStr, buf);

	ASSERT(!mclBnG1_hashAndMapTo(&P, "this", 4));
	ASSERT(!mclBnG2_hashAndMapTo(&Q, "that", 4));
	ASSERT(mclBnG1_getStr(buf, sizeof(buf), &P, 16));
	printf("P = %s\n", buf);
	ASSERT(mclBnG2_getStr(buf, sizeof(buf), &Q, 16));
	printf("Q = %s\n", buf);

	size_t len = 0;
	len = mclBnG1_serialize(buf, sizeof(buf), &P);
	printf("serialize P(size=%d) =:\n", len);
	for(int i=0;i<len;i++) {
		printf("%d,", (unsigned char)buf[i]);
	}
	printf("\n");
	int iEqual = 0;
	mclBnG1 pp;
	mclBnG1_deserialize(&pp, buf, len);
	iEqual = mclBnG1_isEqual(&P, &pp);
	printf("mclBnG1_isEqual(&P, &pp)=%d \n", iEqual);

	len = mclBnG2_serialize(buf, sizeof(buf), &Q);
	printf("serialize Q(size=%d) =:\n", len);
	for(int i=0;i<len;i++) {
		printf("%d,", (unsigned char)buf[i]);
	}
	printf("\n");
	iEqual = 0;
	mclBnG2 qq;
	mclBnG2_deserialize(&qq, buf, len);
	iEqual = mclBnG2_isEqual(&Q, &qq);
	printf("mclBnG1_isEqual(&Q, &qq)=%d \n", iEqual);

	mclBnG1_mul(&aP, &P, &a);
	mclBnG2_mul(&bQ, &Q, &b);

	mclBn_pairing(&e, &P, &Q);
	ASSERT(mclBnGT_getStr(buf, sizeof(buf), &e, 16));
	printf("e = %s\n", buf);
	len = mclBnGT_serialize(buf, sizeof(buf), &e);
	printf("serialize e(size=%d) =:\n", len);
	for(int i=0;i<len;i++) {
		printf("%d,", (unsigned char)buf[i]);
	}
	printf("\n");
	iEqual = 0;
	mclBnGT ee;
	mclBnGT_deserialize(&ee, buf, len);
	iEqual = mclBnGT_isEqual(&e, &ee);
	printf("mclBnG1_isEqual(&e, &ee)=%d \n", iEqual);
	mclBnGT_pow(&e1, &e, &a);
	mclBn_pairing(&e2, &aP, &Q);
	ASSERT(mclBnGT_isEqual(&e1, &e2));

	mclBnGT_pow(&e1, &e, &b);
	mclBn_pairing(&e2, &P, &bQ);
	ASSERT(mclBnGT_isEqual(&e1, &e2));
	if (g_err) {
		printf("err %d\n", g_err);
	} else {
		printf("no err\n");
	}

	unsigned char rand[21];
	memset(rand, 0x00, sizeof(rand));
    sgx_read_rand(rand, 20);
	
	printf("******************sgx_read_rand: %s\n", rand);
	for(int i=0;i<20;i++)
	{
		printf("%02x", rand[i]);
	}
	printf("\n");
	// const char *FpStr = "17465464563654345ABCDEF2345";
	mclBnFp randFp;
	// mclBnFp_setStr(&randFp, FpStr, strlen(FpStr), 16);
	mclBnFp_setHashOf(&randFp, rand, strlen((char*)rand));
	len = mclBnFp_serialize(buf, sizeof(buf), &randFp);
	printf("serialize FP(size=%d) =:\n", len);
	for(int i=0;i<len;i++) {
		printf("%d,", (unsigned char)buf[i]);
	}
	printf("\n");

	return 0;

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
