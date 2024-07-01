/*
 * AWS IoT Device SDK for Embedded C 202211.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef DEMO_CONFIG_H_
#define DEMO_CONFIG_H_

/* Kernel includes. */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/**************************************************/
/******* DO NOT CHANGE the following order ********/
/**************************************************/

/* Include logging header files and define logging macros in the following order:
 * 1. Include the header file "logging_levels.h".
 * 2. Define LIBRARY_LOG_NAME and  LIBRARY_LOG_LEVEL.
 * 3. Include the header file "logging_stack.h".
 */

/* Include header that defines log levels. */
#include "logging_levels.h"

/* Logging configuration for the Demo. */
#ifndef LIBRARY_LOG_NAME
    #define LIBRARY_LOG_NAME    "FLEET_PROVISIONING_DEMO"
#endif

#ifndef LIBRARY_LOG_LEVEL
    #define LIBRARY_LOG_LEVEL    LOG_INFO
#endif

#include "logging_stack.h"

/************ End of logging configuration ****************/

/**
 * @brief Details of the MQTT broker to connect to.
 *
 * This is the Thing's Rest API Endpoint for AWS IoT.
 *
 * @note Your AWS IoT Core endpoint can be found in the AWS IoT console under
 * Settings/Custom Endpoint, or using the describe-endpoint API.
 */
#define AWS_IOT_ENDPOINT               CONFIG_MQTT_BROKER_ENDPOINT

/**
 * @brief AWS IoT MQTT broker port number.
 *
 * In general, port 8883 is for secured MQTT connections.
 *
 * @note Port 443 requires use of the ALPN TLS extension with the ALPN protocol
 * name. When using port 8883, ALPN is not required.
 */
#define AWS_MQTT_PORT    ( CONFIG_MQTT_BROKER_PORT )

/**
 * @brief Path of the file containing the server's root CA certificate.
 *
 * This certificate is used to identify the AWS IoT server and is publicly
 * available. Refer to the AWS documentation available in the link below
 * https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html#server-authentication-certs
 *
 * Amazon's root CA certificate is automatically downloaded to the certificates
 * directory from @ref https://www.amazontrust.com/repository/AmazonRootCA1.pem
 * using the CMake build system.
 *
 * @note This certificate should be PEM-encoded.
 * @note This path is relative from the demo binary created. Update
 * ROOT_CA_CERT_PATH to the absolute path if this demo is executed from elsewhere.
 */
#ifndef ROOT_CA_CERT_PATH
    #define ROOT_CA_CERT_PATH    "/spiffs/certs/AmazonRootCA1.crt"
#endif

/**
 * @brief Path of the file containing the provisioning claim certificate. This
 * certificate is used to connect to AWS IoT Core and use Fleet Provisioning
 * APIs to provision the client device. This is used for the "Provisioning by
 * Claim" provisioning workflow.
 *
 * For information about provisioning by claim, see the following AWS documentation:
 * https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html#claim-based
 *
 * @note This certificate should be PEM-encoded. The certificate should be
 * registered on AWS IoT Core beforehand. It should have an AWS IoT policy to
 * allow it to access only the Fleet Provisioning APIs. An example policy for
 * the claim certificates for this demo is available in the
 * example_claim_policy.json file in the demo directory. In the example,
 * replace <aws-region> with your AWS region, <aws-account-id> with your
 * account ID, and <template-name> with the name of your provisioning template.
 *
 * 
 */
#define CLAIM_CERT_PATH    "/spiffs/certs/claim_cert.crt"

/**
 * @brief Path of the file containing the provisioning claim private key. This
 * key corresponds to the provisioning claim certificate and is used to
 * authenticate with AWS IoT for provisioning by claim.
 *
 * For information about provisioning by claim, see the following AWS documentation:
 * https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html#claim-based
 *
 * @note This private key should be PEM-encoded.
 *
 * 
 */
#define CLAIM_PRIVATE_KEY_PATH    "/spiffs/certs/claim_private.key"

/**
 * @brief Name of the provisioning template to use for the RegisterThing
 * portion of the Fleet Provisioning workflow.
 *
 * For information about provisioning templates, see the following AWS documentation:
 * https://docs.aws.amazon.com/iot/latest/developerguide/provision-template.html#fleet-provision-template
 *
 * The example template used for this demo is available in the
 * example_demo_template.json file in the demo directory. In the example,
 * replace <provisioned-thing-policy> with the policy provisioned devices
 * should have.  The demo template uses Fn::Join to construct the Thing name by
 * concatenating fp_demo_ and the serial number sent by the demo.
 *
 * @note The provisioning template MUST be created in AWS IoT before running the
 * demo.
 */
#define PROVISIONING_TEMPLATE_NAME    CONFIG_PROVISIONING_TEMPLATE_NAME

/**
 * @brief Serial number to send in the request to the Fleet Provisioning
 * RegisterThing API.
 *
 * This is sent as a parameter to the provisioning template, which uses it to
 * generate a unique Thing name. This should be unique per device.
 *
 */
#define DEVICE_SERIAL_NUMBER    CONFIG_DEVICE_SERIAL_NUMBER

/**
 * @brief Subject name to use when creating the certificate signing request (CSR)
 * for provisioning the demo client with using the Fleet Provisioning
 * CreateCertificateFromCsr APIs.
 *
 * This is passed to MbedTLS; see https://tls.mbed.org/api/x509__csr_8h.html#a954eae166b125cea2115b7db8c896e90
 */
#ifndef CSR_SUBJECT_NAME
    #define CSR_SUBJECT_NAME    "CN=Fleet Provisioning Cert"
#endif

/**
 * @brief MQTT client identifier.
 *
 * No two clients may use the same client identifier simultaneously.
 *
 * @note The client identifier should match the Thing name per
 * AWS IoT Security best practices:
 * https://docs.aws.amazon.com/iot/latest/developerguide/security-best-practices.html
 * However, it is not required for the demo to run.
 */
#ifndef CLIENT_IDENTIFIER
    #define CLIENT_IDENTIFIER    DEVICE_SERIAL_NUMBER
#endif

/**
 * @brief Size of the network buffer for MQTT packets. Must be large enough to
 * hold the GetCertificateFromCsr response, which, among other things, includes
 * a PEM encoded certificate.
 */
#define NETWORK_BUFFER_SIZE       ( CONFIG_MQTT_NETWORK_BUFFER_SIZE )

/**
 * @brief The name of the operating system that the application is running on.
 * The current value is given as an example. Please update for your specific
 * operating system.
 */
#define OS_NAME                   "FreeRTOS"

/**
 * @brief The version of the operating system that the application is running
 * on. The current value is given as an example. Please update for your specific
 * operating system version.
 */
#define OS_VERSION                tskKERNEL_VERSION_NUMBER

/**
 * @brief The name of the hardware platform the application is running on. The
 * current value is given as an example. Please update for your specific
 * hardware platform.
 */
#define HARDWARE_PLATFORM_NAME    CONFIG_HARDWARE_PLATFORM_NAME

/**
 * @brief The name of the MQTT library used and its version, following an "@"
 * symbol.
 */
#include "core_mqtt.h"
#define MQTT_LIB    "core-mqtt@" MQTT_LIBRARY_VERSION

/**
 * @brief Predefined thing name.
 *
 * This is the example predefine thing name and could be compiled in ROM code.
 */
#define THING_NAME           "ESP32Thing_" CONFIG_MQTT_CLIENT_IDENTIFIER

/**
 * @brief The length of #THING_NAME.
 */
#define THING_NAME_LENGTH    ( ( uint16_t ) ( sizeof( THING_NAME ) - 1 ) )

/**
 * @brief Predefined shadow name.
 *
 * Defaults to unnamed "Classic" shadow. Change to a custom string to use a named shadow.
 */
#ifndef SHADOW_NAME
    #define SHADOW_NAME    SHADOW_NAME_CLASSIC
#endif

/**
 * @brief The length of #SHADOW_NAME.
 */
#define SHADOW_NAME_LENGTH    ( ( uint16_t ) ( sizeof( SHADOW_NAME ) - 1 ) )

/**
 * @brief AWS IoT Core server port number for HTTPS connections.
 *
 * For this demo, an X.509 certificate is used to verify the client.
 *
 * @note Port 443 requires use of the ALPN TLS extension with the ALPN protocol
 * name being x-amzn-http-ca. When using port 8443, ALPN is not required.
 */
#ifndef AWS_HTTPS_PORT
    #define AWS_HTTPS_PORT    443
#endif

/**
 * @brief Configure application version.
 */

#define APP_VERSION_MAJOR         0
#define APP_VERSION_MINOR         0
#define APP_VERSION_BUILD         1

/**
 * @brief The name of the library used and its version, following an "@"
 * symbol.
 */
#define OTA_LIB                   "otalib@1.0.0"

#endif /* ifndef DEMO_CONFIG_H_ */
