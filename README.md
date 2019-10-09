## MQTT Download Agent

### This project contains a library for downloading files from AWS IoT over the shared MQTT connection.

The library has been pre-integrated with [aws-iot-device-sdk-embedded-C](https://github.com/aws/aws-iot-device-sdk-embedded-C). There is also a sample application that demonstrates how to use the library’s API.

The API of this library is documented in `include/aws_iot_download_agent.h`.

For instruction on how to create a stream in AWS IoT to supply the file for downloading, see `samples/linux/download_agent_sample/README.md`.

To learn how to use this library’s API, see `samples/linux/download_agent_sample/download_agent_sample.c.`

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

## License

This project is licensed under the Apache-2.0 License.
