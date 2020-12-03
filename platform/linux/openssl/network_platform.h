/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef IOTSDKC_NETWORK_OPENSSL_PLATFORM_H_H

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/crypto.h"
#include "openssl/opensslv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief TLS Connection Parameters
 *
 * Defines a type containing TLS specific parameters to be passed down to the
 * TLS networking layer to create a TLS secured socket.
 */
typedef struct _TLSDataParams
{
    int32_t xTcpSocket;
    SSL * pSsl;
    uint32_t flags;
} TLSDataParams;

#define IOTSDKC_NETWORK_OPENSSL_PLATFORM_H_H

#ifdef __cplusplus
}
#endif

#endif //IOTSDKC_NETWORK_OPENSSL_PLATFORM_H_H
