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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <string.h>
#include <timer_platform.h>
#include <network_interface.h>

#include "aws_iot_error.h"
#include "aws_iot_log.h"
#include "network_interface.h"
#include "network_platform.h"

#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/*-----------------------------------------------------------*/

static IoT_Error_t connectToAddress( struct sockaddr * pAddrInfo,
                                     uint16_t port,
                                     int32_t tcpSocket )
{
    IoT_Error_t returnStatus = SUCCESS;
    int connectStatus = 0;
    socklen_t addrInfoLength = 0;
    uint16_t netPort = 0;
    struct sockaddr_in * pIpv4Address;
    struct sockaddr_in6 * pIpv6Address;

    if( pAddrInfo == NULL )
    {
        IOT_ERROR( "Parameter check failed: pAddrInfo is NULL.\n" );
        returnStatus = NULL_VALUE_ERROR;
    }
    else if( pAddrInfo->sa_family != AF_INET && pAddrInfo->sa_family != AF_INET6 )
    {
        IOT_ERROR( "Invalid IP address family.\n" );
        returnStatus = TCP_SETUP_ERROR;
    }
    else if( tcpSocket < 0 )
    {
        IOT_ERROR( "Invalid socket.\n" );
        returnStatus = TCP_SETUP_ERROR;
    }
    else
    {
        /* Empty else. */
    }

    if( returnStatus == SUCCESS )
    {
        netPort = htons( port );

        if( pAddrInfo->sa_family == ( sa_family_t ) AF_INET )
        {
            pIpv4Address = ( struct sockaddr_in * ) pAddrInfo;
            pIpv4Address->sin_port = netPort;
            addrInfoLength = ( socklen_t ) sizeof( struct sockaddr_in );
        }
        else
        {
            pIpv6Address = ( struct sockaddr_in6 * ) pAddrInfo;
            pIpv6Address->sin6_port = netPort;
            addrInfoLength = ( socklen_t ) sizeof( struct sockaddr_in6 );
        }

        IOT_DEBUG( "Attempting to connect to server.\n" );
        connectStatus = connect( tcpSocket,
                                 pAddrInfo,
                                 addrInfoLength );
        if( connectStatus == -1 )
        {
            IOT_WARN( "Failed to connect to server.\n" );
            ( void ) close( tcpSocket );
            returnStatus = TCP_CONNECTION_ERROR;
        }
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/
static IoT_Error_t socketsConnect( int32_t * pTcpSocket,
                                   const char * pHostName,
                                   uint16_t port,
                                   uint32_t sendTimeoutMs,
                                   uint32_t recvTimeoutMs )
{
    IoT_Error_t returnStatus = SUCCESS;
    int result = 0;
    struct addrinfo hints = { 0 };
    struct addrinfo * pListHead = NULL;
    struct addrinfo * pIndex = NULL;
    struct timeval transportTimeout = { 0 };

    if( pTcpSocket == NULL )
    {
        IOT_ERROR( "Parameter check failed: pTcpSocket is NULL.\n" );
        returnStatus = NULL_VALUE_ERROR;
    }
    else if( pHostName == NULL )
    {
        IOT_ERROR( "Parameter check failed: pHostName is NULL.\n" );
        returnStatus = NULL_VALUE_ERROR;
    }
    else
    {
        /* Empty else. */
    }

    if( returnStatus == SUCCESS )
    {
        /* Add hints to retrieve only TCP sockets in getaddrinfo. */
        ( void ) memset( &hints, 0, sizeof( hints ) );
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = ( int32_t ) SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        if( ( result = getaddrinfo( pHostName,
                                    NULL,
                                    &hints,
                                    &pListHead ) ) != 0 )
        {
            IOT_ERROR( "Failed to resolve DNS: Hostname=%s, ErrorCode=%d.\n", pHostName, result );
            returnStatus = FAILURE;
        }
    }

    if( returnStatus == SUCCESS )
    {
        IOT_DEBUG( "Attempt connecting.\n" );
        returnStatus = TCP_CONNECTION_ERROR;
        for( pIndex = pListHead; pIndex != NULL; pIndex = pIndex->ai_next )
        {
            *pTcpSocket = socket( pIndex->ai_family,
                                  pIndex->ai_socktype,
                                  pIndex->ai_protocol );
            if( *pTcpSocket == -1 )
            {
                continue;
            }

            returnStatus = connectToAddress( pIndex->ai_addr,
                                             port,
                                             *pTcpSocket );
            if( returnStatus == SUCCESS )
            {
                break;
            }
        }

        if( returnStatus == SUCCESS )
        {
            IOT_DEBUG( "Established TCP connection.\n" );
        }
        else
        {
            IOT_ERROR( "Failed to connect.\n" );
        }
        freeaddrinfo( pListHead );
    }

    if( returnStatus == SUCCESS )
    {
        transportTimeout.tv_sec = ( ( ( int64_t ) sendTimeoutMs ) / 1000 );
        transportTimeout.tv_usec = ( 1000 * ( ( ( int64_t ) sendTimeoutMs ) % 1000 ) );

        result = setsockopt( *pTcpSocket,
                             SOL_SOCKET,
                             SO_SNDTIMEO,
                             &transportTimeout,
                             ( socklen_t ) sizeof( transportTimeout ) );
        if( result == -1 )
        {
            IOT_ERROR( "Setting socket send timeout failed.\n" );
            returnStatus = TCP_SETUP_ERROR;
        }
    }

    if( returnStatus == SUCCESS )
    {
        transportTimeout.tv_sec = ( ( ( int64_t ) recvTimeoutMs ) / 1000 );
        transportTimeout.tv_usec = ( 1000 * ( ( ( int64_t ) recvTimeoutMs ) % 1000 ) );

        result = setsockopt( *pTcpSocket,
                             SOL_SOCKET,
                             SO_RCVTIMEO,
                             &transportTimeout,
                             ( socklen_t ) sizeof( transportTimeout ) );
        if( result == -1 )
        {
            IOT_ERROR( "Setting socket receive timeout failed.\n" );
            returnStatus = TCP_SETUP_ERROR;
        }
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

static IoT_Error_t socketDisconnect( int32_t xTcpSocket )
{
    IoT_Error_t returnStatus = SUCCESS;

    if( xTcpSocket > 0 )
    {
        ( void ) shutdown( xTcpSocket, SHUT_RDWR );
        ( void ) close( xTcpSocket );
    }
    else
    {
        IOT_ERROR( "Parameter check failed: xTcpSocket was negative." );
        returnStatus = FAILURE;
    }
    
    return returnStatus;
}
/*-----------------------------------------------------------*/

static IoT_Error_t setRootCa( const SSL_CTX * pSslContext,
                              const char * pRootCaPath )
{
    IoT_Error_t returnStatus = SUCCESS;
    FILE * pRootCaFile = NULL;
    X509 * pRootCa = NULL;

    if( pSslContext == NULL )
    {
        IOT_ERROR( "Parameter check failed: pSslContext is NULL.\n" );
        returnStatus = NULL_VALUE_ERROR;
    }
    else if( pRootCaPath == NULL )
    {
        IOT_ERROR( "Parameter check failed: pRootCaPath is NULL.\n" );
        returnStatus = NULL_VALUE_ERROR;
    }
    else
    {
        /* Empty else. */
    }

    if( returnStatus == SUCCESS )
    {
        pRootCaFile = fopen( pRootCaPath,
                             "r" );
        if( pRootCaFile == NULL )
        {
            IOT_ERROR( "fopen failed to find the root CA certificate file: ROOT_CA_PATH=%s.\n", pRootCaPath );
            returnStatus = NETWORK_SSL_CERT_ERROR;
        }
    }

    if( returnStatus == SUCCESS )
    {
        pRootCa = PEM_read_X509( pRootCaFile,
                                 NULL,
                                 NULL,
                                 NULL);
        if( pRootCa == NULL )
        {
            IOT_ERROR( "PEM_read_X509 failed to parse root CA.\n" );
            returnStatus = NETWORK_SSL_CERT_ERROR;
        }
    }

    if( returnStatus == SUCCESS )
    {
        if( X509_STORE_add_cert( SSL_CTX_get_cert_store( pSslContext ),
                                 pRootCa ) != 1 )
        {
            IOT_ERROR( "X509_STORE_add_cert failed to add root CA to certificate store.\n" );
            returnStatus = NETWORK_SSL_CERT_ERROR;
        }
    }

    if( pRootCa != NULL )
    {
        ( void ) X509_free( pRootCa );
    }

    if( pRootCaFile != NULL )
    {
        if( fclose( pRootCaFile ) != 0 )
        {
            IOT_WARN( "fclose failed to close file %s\n", pRootCaPath );
        }
    }

    if( returnStatus == SUCCESS )
    {
        IOT_DEBUG( "Successfully imported root CA.\n" );
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

static IoT_Error_t setClientCertificate( SSL_CTX * pSslContext,
                                         const char * pClientCertPath )
{
    IoT_Error_t returnStatus = SUCCESS;

    if( pSslContext == NULL )
    {
        IOT_ERROR( "Parameter check failed: pSslContext is NULL.\n" );
        returnStatus = NULL_VALUE_ERROR;
    }
    else if( pClientCertPath == NULL )
    {
        IOT_ERROR( "Parameter check failed: pClientCertPath is NULL.\n" );
        returnStatus = NULL_VALUE_ERROR;
    }
    else
    {
        /* Empty else. */
    }

    if( returnStatus == SUCCESS )
    {
        if( SSL_CTX_use_certificate_chain_file( pSslContext,
                                                pClientCertPath ) != 1 )
        {
            IOT_ERROR( "SSL_CTX_use_certificate_chain_file failed to import client certificate at %s.\n", pClientCertPath );
            returnStatus = NETWORK_SSL_CERT_ERROR;
        }
    }

    if( returnStatus == SUCCESS )
    {
        IOT_DEBUG( "Successfully imported client certificate.\n" );
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

static IoT_Error_t setPrivateKey( SSL_CTX * pSslContext,
                                  const char * pPrivateKeyPath )
{
    IoT_Error_t returnStatus = SUCCESS;

    if( pSslContext == NULL )
    {
        IOT_ERROR( "Parameter check failed: pSslContext is NULL.\n" );
        returnStatus = NULL_VALUE_ERROR;
    }
    else if( pPrivateKeyPath == NULL )
    {
        IOT_ERROR( "Parameter check failed: pPrivateKeyPath is NULL.\n" );
        returnStatus = NULL_VALUE_ERROR;
    }
    else
    {
        /* Empty else. */
    }

    if( returnStatus == SUCCESS )
    {
        if( SSL_CTX_use_PrivateKey_file( pSslContext,
                                         pPrivateKeyPath,
                                         SSL_FILETYPE_PEM ) != 1 )
        {
            IOT_ERROR( "SSL_CTX_use_PrivateKey_file failed to import client certificate private key at %s.\n", pPrivateKeyPath );
            returnStatus = NETWORK_SSL_CERT_ERROR;
        }
    }

    if( returnStatus == SUCCESS )
    {
        IOT_DEBUG( "Successfully imported client certificate private key.\n" );
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

static IoT_Error_t setCredentials( SSL_CTX * pSslContext,
                                   const char * pRootCaPath,
                                   const char * pClientCertPath,
                                   const char * pPrivateKeyPath )
{
    IoT_Error_t returnStatus = FAILURE;

    if( pSslContext == NULL )
    {
        IOT_ERROR( "Invalid address info.\n" );
        returnStatus = NULL_VALUE_ERROR;
    }
    else
    {
        if( pRootCaPath != NULL )
        {
            returnStatus = setRootCa( pSslContext,
                                      pRootCaPath );
        }

        if( ( returnStatus == SUCCESS ) &&
            ( pClientCertPath != NULL ) )
        {
            returnStatus = setClientCertificate( pSslContext,
                                                 pClientCertPath );
        }

        if( ( returnStatus == SUCCESS ) &&
            ( pPrivateKeyPath != NULL ) )
        {
            returnStatus = setPrivateKey( pSslContext,
                                          pPrivateKeyPath );
        }
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

static IoT_Error_t tlsConnect( TLSConnectParams * connParams,
                               TLSDataParams * dataParams )
{
    IoT_Error_t returnStatus = SUCCESS;
    int result = 0;
    SSL_CTX * pSslContext = NULL;
    uint8_t sslObjectCreated = 0;
    const char * alpnProtocols = "\x0ex-amzn-mqtt-ca";

    if( returnStatus == SUCCESS )
    {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || (OPENSSL_VERSION_NUMBER >= 0x20000000L)
        pSslContext = SSL_CTX_new( TLSv1_2_client_method() );
#else
        pSslContext = SSL_CTX_new( TLS_client_method() );
#endif
        if( pSslContext == NULL )
        {
            IOT_ERROR( "Creation of a new SSL_CTX object failed.\n" );
            returnStatus = NETWORK_SSL_INIT_ERROR;
        }
    }

    if( returnStatus == SUCCESS )
    {
        ( void ) SSL_CTX_set_mode( pSslContext,
                                   ( long ) SSL_MODE_AUTO_RETRY );

        if( setCredentials( pSslContext,
                            connParams->pRootCALocation,
                            connParams->pDeviceCertLocation,
                            connParams->pDevicePrivateKeyLocation ) != SUCCESS )
        {
            IOT_ERROR( "Setting up credentials failed.\n" );
            returnStatus = NETWORK_SSL_CERT_ERROR;
        }
    }

    if( returnStatus == SUCCESS )
    {
        dataParams->pSsl = SSL_new( pSslContext );
        if( dataParams->pSsl == NULL )
        {
            IOT_ERROR( "SSL_new failed to create a new SSL context.\n" );
            returnStatus = NETWORK_SSL_INIT_ERROR;
        }
        else
        {
            sslObjectCreated = 1u;
        }
    }

    if( returnStatus == SUCCESS )
    {
        ( void ) SSL_set_verify( dataParams->pSsl,
                                 SSL_VERIFY_PEER,
                                 NULL );

        result = SSL_set_fd( dataParams->pSsl,
                             dataParams->xTcpSocket );
        if( result != 1 )
        {
            IOT_ERROR( "SSL_set_fd failed to set the socket fd to SSL context.\n" );
            returnStatus = NETWORK_SSL_INIT_ERROR;
        }
    }

    if( returnStatus == SUCCESS && connParams->DestinationPort == 443 )
    {
        result = SSL_set_alpn_protos( dataParams->pSsl,
                                      alpnProtocols,
                                      strlen(alpnProtocols) );
        if( result != 0 )
        {
            IOT_ERROR( "SSL_set_alpn_protos failed to ALPN protocols.\n" );
            returnStatus = NETWORK_SSL_INIT_ERROR;
        }
    }

    if( returnStatus == SUCCESS )
    {
        result = SSL_connect( dataParams->pSsl );
        if( result != 1 )
        {
            IOT_ERROR( "SSL_connect failed to perform TLS handshake.\n" );
            returnStatus = SSL_CONNECTION_ERROR;
        }
    }

    if( returnStatus == SUCCESS )
    {
        result = SSL_get_verify_result( dataParams->pSsl );
        if( result != X509_V_OK )
        {
            IOT_ERROR( "SSL_get_verify_result failed to verify X509 certificate from peer.\n" );
            returnStatus = SSL_CONNECTION_ERROR;
        }
    }

    if( pSslContext != NULL )
    {
        ( void ) SSL_CTX_free( pSslContext );
    }

    if( returnStatus != SUCCESS && sslObjectCreated == 1u )
    {
        ( void ) SSL_free( dataParams->pSsl );
        dataParams->pSsl = NULL;
    }

    if( returnStatus == SUCCESS )
    {
        IOT_INFO( "Established a TLS connection.\n" );
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

IoT_Error_t iot_tls_init( Network * pNetwork,
                          char * pRootCALocation,
                          char * pDeviceCertLocation,
                          char * pDevicePrivateKeyLocation,
                          char * pDestinationURL,
                          uint16_t destinationPort,
                          uint32_t timeout_ms,
                          bool ServerVerificationFlag )
{
    IoT_Error_t returnStatus = SUCCESS;

    pNetwork->tlsConnectParams.DestinationPort = destinationPort;
    pNetwork->tlsConnectParams.pDestinationURL = pDestinationURL;
    pNetwork->tlsConnectParams.pDeviceCertLocation = pDeviceCertLocation;
    pNetwork->tlsConnectParams.pDevicePrivateKeyLocation = pDevicePrivateKeyLocation;
    pNetwork->tlsConnectParams.pRootCALocation = pRootCALocation;
    pNetwork->tlsConnectParams.timeout_ms = timeout_ms;
    pNetwork->tlsConnectParams.ServerVerificationFlag = ServerVerificationFlag;

    pNetwork->connect = iot_tls_connect;
    pNetwork->read = iot_tls_read;
    pNetwork->write = iot_tls_write;
    pNetwork->disconnect = iot_tls_disconnect;
    pNetwork->isConnected = iot_tls_is_connected;
    pNetwork->destroy = iot_tls_destroy;

    ( void ) SSL_library_init();
    OpenSSL_add_all_algorithms();

    return returnStatus;
}
/*-----------------------------------------------------------*/

IoT_Error_t iot_tls_is_connected( Network * pNetwork )
{
    /* Use this to add implementation which can check for physical layer disconnect */
    return NETWORK_PHYSICAL_LAYER_CONNECTED;
}
/*-----------------------------------------------------------*/

IoT_Error_t iot_tls_connect( Network * pNetwork,
                             TLSConnectParams * params )
{
    IoT_Error_t returnStatus = SUCCESS;

    if( pNetwork == NULL )
    {
        IOT_ERROR( "Invalid network parameters.\n" );
        returnStatus = NULL_VALUE_ERROR;
    }
    else if( socketsConnect( &( pNetwork->tlsDataParams.xTcpSocket ),
                             pNetwork->tlsConnectParams.pDestinationURL,
                             pNetwork->tlsConnectParams.DestinationPort,
                             pNetwork->tlsConnectParams.timeout_ms,
                             pNetwork->tlsConnectParams.timeout_ms ) != SUCCESS )
    {
        IOT_ERROR( "Failed at connecting to %s:%d\n", pNetwork->tlsConnectParams.pDestinationURL,
                                                      pNetwork->tlsConnectParams.DestinationPort );
        returnStatus = TCP_CONNECTION_ERROR;
    }
    else if( tlsConnect( &pNetwork->tlsConnectParams,
                         &pNetwork->tlsDataParams ) != SUCCESS )
    {
        IOT_ERROR( "Failed at establishing TLS connection\n" );
        returnStatus = SSL_CONNECTION_ERROR;
    }
    else
    {
        /* Empty else. */
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

IoT_Error_t iot_tls_write( Network * pNetwork,
                           unsigned char * pMsg,
                           size_t len,
                           Timer * timer,
                           size_t * written_len )
{
    IoT_Error_t returnStatus = SUCCESS;
    SSL * pSsl = NULL;
    int xBytesSent = 0;
    size_t bytesWritten = 0;
    int sslError = 0;

    pSsl = pNetwork->tlsDataParams.pSsl;

    if( pSsl == NULL )
    {
        return NETWORK_SSL_WRITE_ERROR;
    }

    do
    {
        xBytesSent = SSL_write( pSsl,
                                pMsg + bytesWritten,
                                len - bytesWritten );
        if( xBytesSent <= 0 )
        {
            sslError = SSL_get_error( pSsl,
                                      xBytesSent );
            if( sslError != SSL_ERROR_WANT_WRITE )
            {
                IOT_ERROR( "Failed to send data over network: SSL_write of OpenSSL failed: ErrorStatus=%s.\n", ERR_reason_error_string( sslError ) );
                returnStatus = NETWORK_SSL_WRITE_ERROR;
                break;
            }
        }
        else
        {
            bytesWritten += xBytesSent;
            if( bytesWritten >= len )
            {
                break;
            }
        }
    } while ( !has_timer_expired( timer ) );

    if( returnStatus == SUCCESS && bytesWritten != len )
    {
        returnStatus = NETWORK_SSL_WRITE_TIMEOUT_ERROR;
    }

    *written_len = bytesWritten;

    return returnStatus;
}
/*-----------------------------------------------------------*/

IoT_Error_t iot_tls_read( Network * pNetwork,
                          unsigned char * pMsg,
                          size_t len,
                          Timer * timer,
                          size_t * read_len )
{
    IoT_Error_t returnStatus = SUCCESS;
    SSL * pSsl = NULL;
    int xBytesReceived = 0;
    size_t bytesRead = 0;
    int sslError = 0;

    pSsl = pNetwork->tlsDataParams.pSsl;

    if( pSsl == NULL )
    {
        return NETWORK_SSL_READ_ERROR;
    }

    do
    {
        xBytesReceived = SSL_read( pSsl,
                                   pMsg + bytesRead,
                                   len - bytesRead );
        if( xBytesReceived <= 0 )
        {
            sslError = SSL_get_error( pSsl,
                                      xBytesReceived );
            if( sslError != SSL_ERROR_WANT_READ )
            {
                IOT_ERROR( "Failed to receive data over network: SSL_read failed: ErrorStatus=%s.\n", ERR_reason_error_string( sslError ) );
                returnStatus = NETWORK_SSL_READ_ERROR;
                break;
            }
        }
        else
        {
            bytesRead += xBytesReceived;
            if( bytesRead >= len )
            {
                break;
            }
        }
    } while ( !has_timer_expired( timer ) );

    if( returnStatus == SUCCESS && bytesRead != len )
    {
        if( bytesRead > 0 )
        {
            returnStatus = NETWORK_SSL_READ_TIMEOUT_ERROR;
        }
        else
        {
            returnStatus = NETWORK_SSL_NOTHING_TO_READ;
        }
    }

    *read_len = bytesRead;

    return returnStatus;
}
/*-----------------------------------------------------------*/

IoT_Error_t iot_tls_disconnect( Network * pNetwork )
{
    IoT_Error_t returnStatus = SUCCESS;
    SSL * pSsl = NULL;

    pSsl = pNetwork->tlsDataParams.pSsl;

    if( pSsl != NULL )
    {
        /* SSL shutdown should be called twice: once to send "close notify" and
         * once more to receive the peer's "close notify". */
        if( SSL_shutdown( pSsl ) == 0 )
        {
            ( void ) SSL_shutdown( pSsl );
        }

        ( void ) SSL_free( pSsl );
    }

    pNetwork->tlsDataParams.pSsl = NULL;

    ( void ) socketDisconnect( pNetwork->tlsDataParams.xTcpSocket );

    pNetwork->tlsDataParams.xTcpSocket = 0;

    return returnStatus;
}
/*-----------------------------------------------------------*/

IoT_Error_t iot_tls_destroy( Network * pNetwork )
{
    return SUCCESS;
}
/*-----------------------------------------------------------*/

#ifdef __cplusplus
}
#endif
