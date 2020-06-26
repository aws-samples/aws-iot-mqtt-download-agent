## MQTT Download Agent

### This project contains a library for downloading files from AWS IoT over a MQTT connection.

The library has been pre-integrated with [aws-iot-device-sdk-embedded-C](https://github.com/aws/aws-iot-device-sdk-embedded-C). There is also a [sample application](https://github.com/aws-samples/aws-iot-mqtt-download-agent/tree/master/samples/linux/download_agent_sample) that demonstrates how to use the library’s API.

The theory of operations and API of this library is documented in [`include/aws_iot_download_agent.h`](https://github.com/aws-samples/aws-iot-mqtt-download-agent/blob/master/include/aws_iot_download_agent.h).

For instruction on how to create a stream in AWS IoT to supply the file for downloading, see [`samples/linux/download_agent_sample/README.md`](https://github.com/aws-samples/aws-iot-mqtt-download-agent/blob/master/samples/linux/download_agent_sample/README.md).

To learn how to use this library’s API, see [`samples/linux/download_agent_sample/download_agent_sample.c.`](https://github.com/aws-samples/aws-iot-mqtt-download-agent/blob/master/samples/linux/download_agent_sample/download_agent_sample.c)

This project is based on the master branch of [aws-iot-device-sdk-embedded-C](https://github.com/aws/aws-iot-device-sdk-embedded-C). It added/modified the following files:
- external_libs/tinycbor/README added – Pointer to where to download tinycbor, the externally depended library.
- include/aws_iot_download_agent.h added – External API of the library.
- include/aws_iot_download_agent_config.h added – Configuration parameters used by the library. These can be changed for your own system.
- include/aws_iot_download_cbor.h added – Wrapper API for the cbor protocol. You do not need to change this.
- include/aws_iot_download_cbor_internal.h added - Wrapper API for the cbor protocol. You do not need to change this.
- include/aws_iot_error.h (15 added, 1 deleted) – Error codes returned by the library’s API.
- samples/README.md (4 added, 1 deleted) – A brief description of the sample application.
- samples/linux/download_agent_sample/Makefile added – Makefile for building the sample application.
- samples/linux/download_agent_sample/README.md added - User manual for creating streams in AWS IoT cloud, from which this library can download files.
- samples/linux/download_agent_sample/aws_iot_config.h added – Configuration parameters for building the sample application. You must edit this file and input values for your own AWS IoT account, certificate and private key for the IoT thing, etc.
- samples/linux/download_agent_sample/download_agent_sample.c added – The sample application that use the library to download a file.
- src/aws_iot_download_agent.c added – Source code of the library.
- src/aws_iot_download_cbor.c added – Source code of the wrapper for cbor.

### Building the example

#### Linux Ubuntu 16.04 LTS
All development and testing of the MQTT Download Agent Sample has been performed on Linux Ubuntu 16.04 LTS.

#### Installing Dependencies
```
sudo apt-get update
sudo apt-get install build-essential \
                     python \
                     clang
```

#### Get mbedtls and tinyCBOR
```
wget -qO- https://github.com/ARMmbed/mbedtls/archive/mbedtls-2.18.1.tar.gz | tar xvz -C external_libs/mbedTLS --strip-components=1
wget -qO- https://github.com/ARMmbed/mbed-crypto/archive/mbedcrypto-1.1.1.tar.gz | tar xvz -C external_libs/mbedTLS/crypto --strip-components=1
wget -qO- https://github.com/intel/tinycbor/archive/v0.5.2.tar.gz | tar xvz -C external_libs/tinycbor --strip-components=1
```

#### Configure the SDK with your device parameters
1. [Create and Activate a Device Certificate](https://docs.aws.amazon.com/iot/latest/developerguide/create-device-certificate.html)

2. Copy the certificate, private key, and root CA certificate you created into the [`/certs`](https://github.com/aws-samples/aws-iot-mqtt-download-agent/tree/master/certs) directory.

3. You must configure the sample with your own AWS IoT endpoint, private key, certificate, and root CA certificate. Make those changes in the [`samples/linux/download_agent_sample/aws_iot_config.h`](https://github.com/aws-samples/aws-iot-mqtt-download-agent/blob/master/samples/linux/download_agent_sample/aws_iot_config.h) file. Open the `aws_iot_config.h` file, update the values for the following:
```
// Get from console
// =================================================
#define AWS_IOT_MQTT_HOST              "YOUR_ENDPOINT_HERE" ///< Customer specific MQTT HOST. The same will be used for Thing Shadow
#define AWS_IOT_MQTT_PORT              443 ///< default port for MQTT/S
#define AWS_IOT_MQTT_CLIENT_ID         "YOUR_CLIENT_ID" ///< MQTT client ID should be unique for every device
#define AWS_IOT_MY_THING_NAME          "YOUR_THING_NAME" ///< Thing Name of the Shadow this device is associated with
#define AWS_IOT_ROOT_CA_FILENAME       "rootCA.crt" ///< Root CA file name
#define AWS_IOT_CERTIFICATE_FILENAME   "cert.pem" ///< device signed certificate file name
#define AWS_IOT_PRIVATE_KEY_FILENAME   "privkey.pem" ///< Device private key filename
// =================================================
```

#### Building the download agent sample
```
cd samples/linux/download_agent_sample
make -j4
./download_agent_sample
```

## License

This project is licensed under the Apache-2.0 License.
