/*
 * AWS IoT Device SDK for Embedded C 202211.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * Demo for showing use of the Fleet Provisioning library to use the Fleet
 * Provisioning feature of AWS IoT Core for provisioning devices with
 * credentials. This demo shows how a device can be provisioned with AWS IoT
 * Core using the Certificate Signing Request workflow of the Fleet
 * Provisioning feature.
 *
 * The Fleet Provisioning library provides macros and helper functions for
 * assembling MQTT topics strings, and for determining whether an incoming MQTT
 * message is related to the Fleet Provisioning API of AWS IoT Core. The Fleet
 * Provisioning library does not depend on any particular MQTT library,
 * therefore the functionality for MQTT operations is placed in another file
 * (mqtt_operations.c). This demo uses the coreMQTT library. If needed,
 * mqtt_operations.c can be modified to replace coreMQTT with another MQTT
 * library. This demo requires using the AWS IoT Core broker as Fleet
 * Provisioning is an AWS IoT Core feature.
 *
 * This demo provisions a device certificate using the provisioning by claim
 * workflow with a Certificate Signing Request (CSR). The demo connects to AWS
 * IoT Core using provided claim credentials (whose certificate needs to be
 * registered with IoT Core before running this demo), subscribes to the
 * CreateCertificateFromCsr topics, and obtains a certificate. It then
 * subscribes to the RegisterThing topics and activates the certificate and
 * obtains a Thing using the provisioning template. Finally, it reconnects to
 * AWS IoT Core using the new credentials.
 */

/* Standard includes. */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include <sys/time.h>

/* POSIX includes. */
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

/* Demo config. */
#include "demo_config.h"

/* corePKCS11 includes. */
#include "core_pkcs11.h"
#include "core_pkcs11_config.h"

/* AWS IoT Fleet Provisioning Library. */
#include "fleet_provisioning.h"

/* Demo includes. */
#include "mqtt_operations.h"
#include "pkcs11_operations.h"
#include "fleet_provisioning_serializer.h"

#include "cJSON.h"

/* JSON API header. */
#include "core_json.h"

/* Shadow config include. */
#include "shadow_config.h"

/* SHADOW API header. */
#include "shadow.h"

/**
 * These configurations are required. Throw compilation error if it is not
 * defined.
 */
#ifndef PROVISIONING_TEMPLATE_NAME
    #error "Please define PROVISIONING_TEMPLATE_NAME to the template name registered with AWS IoT Core in demo_config.h."
#endif
#ifndef CLAIM_CERT_PATH
    #error "Please define path to claim certificate (CLAIM_CERT_PATH) in demo_config.h."
#endif
#ifndef CLAIM_PRIVATE_KEY_PATH
    #error "Please define path to claim private key (CLAIM_PRIVATE_KEY_PATH) in demo_config.h."
#endif
#ifndef DEVICE_SERIAL_NUMBER
    #error "Please define a serial number (DEVICE_SERIAL_NUMBER) in demo_config.h."
#endif

#define MQTT_DATA_TOPIC                  "device/" CLIENT_IDENTIFIER "/data"
#define MQTT_DATA_TOPIC_LENGTH           ( ( uint16_t ) ( sizeof( MQTT_DATA_TOPIC ) - 1 ) )

/**
 * @brief The length of #PROVISIONING_TEMPLATE_NAME.
 */
#define PROVISIONING_TEMPLATE_NAME_LENGTH    ( ( uint16_t ) ( sizeof( PROVISIONING_TEMPLATE_NAME ) - 1 ) )

/**
 * @brief The length of #DEVICE_SERIAL_NUMBER.
 */
#define DEVICE_SERIAL_NUMBER_LENGTH          ( ( uint16_t ) ( sizeof( DEVICE_SERIAL_NUMBER ) - 1 ) )

/**
 * @brief Size of AWS IoT Thing name buffer.
 *
 * See https://docs.aws.amazon.com/iot/latest/apireference/API_CreateThing.html#iot-CreateThing-request-thingName
 */
#define MAX_THING_NAME_LENGTH                128

/**
 * @brief The maximum number of times to run the loop in this demo.
 *
 * @note The demo loop is attempted to re-run only if it fails in an iteration.
 * Once the demo loop succeeds in an iteration, the demo exits successfully.
 */
#ifndef FLEET_PROV_MAX_DEMO_LOOP_COUNT
    #define FLEET_PROV_MAX_DEMO_LOOP_COUNT    ( 3 )
#endif

/**
 * @brief Time in seconds to wait between retries of the demo loop if
 * demo loop fails.
 */
#define DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_SECONDS    ( 5 )

/**
 * @brief Size of buffer in which to hold the certificate signing request (CSR).
 */
#define CSR_BUFFER_LENGTH                              2048

/**
 * @brief Size of buffer in which to hold the certificate.
 */
#define CERT_BUFFER_LENGTH                             2048

/**
 * @brief Size of buffer in which to hold the certificate id.
 *
 * See https://docs.aws.amazon.com/iot/latest/apireference/API_Certificate.html#iot-Type-Certificate-certificateId
 */
#define CERT_ID_BUFFER_LENGTH                          64

/**
 * @brief Size of buffer in which to hold the certificate ownership token.
 */
#define OWNERSHIP_TOKEN_BUFFER_LENGTH                  512

/**
 * @brief Status values of the Fleet Provisioning response.
 */
typedef enum
{
    ResponseNotReceived,
    ResponseAccepted,
    ResponseRejected
} ResponseStatus_t;

/**
 * @brief The simulated device current heap state.
 */
static uint32_t currentHeap = 0;

/**
 * @brief The device LED color.
 */
static char currentColor[64] = "WHITE";

/**
 * @brief Format string representing a Shadow document with a "desired" state.
 *
 * The real json document will look like this:
 * {
 *   "state": {
 *     "desired": {
 *       "heap": 1
 *     }
 *   },
 *   "clientToken": "021909"
 * }
 *
 * Note the client token, which is optional for all Shadow updates. The client
 * token must be unique at any given time, but may be reused once the update is
 * completed. For this demo, a timestamp is used for a client token.
 */
#define SHADOW_DESIRED_JSON     \
    "{"                         \
    "\"state\":{"               \
    "\"reported\":{"            \
    "\"color\":\"%s\""          \
    "}"                         \
    "},"                        \
    "\"clientToken\":\"%s\""    \
    "}"

/**
 * @brief The expected size of #SHADOW_DESIRED_JSON.
 *
 * Because all the format specifiers in #SHADOW_DESIRED_JSON include a length,
 * its full actual size is known by pre-calculation, here's the formula why
 * the length need to minus 3:
 * 1. The length of "%01d" is 4.
 * 2. The length of %06lu is 5.
 * 3. The actual length we will use in case 1. is 1 ( for the state of powerOn ).
 * 4. The actual length we will use in case 2. is 6 ( for the clientToken length ).
 * 5. Thus the additional size 3 = 4 + 5 - 1 - 6 + 1 (termination character).
 *
 * In your own application, you could calculate the size of the json doc in this way.
 */
#define SHADOW_DESIRED_JSON_LENGTH    243

/**
 * @brief Format string representing a Shadow document with a "reported" state.
 *
 * The real json document will look like this:
 * {
 *   "state": {
 *     "reported": {
 *       "heap": 1
 *     }
 *   },
 *   "clientToken": "021909"
 * }
 *
 * Note the client token, which is required for all Shadow updates. The client
 * token must be unique at any given time, but may be reused once the update is
 * completed. For this demo, a timestamp is used for a client token.
 */
#define SHADOW_REPORTED_JSON    \
    "{"                         \
    "\"state\":{"               \
    "\"reported\":{"            \
    "\"color\":\"%s\""          \
    "}"                         \
    "},"                        \
    "\"clientToken\":\"%s\""    \
    "}"

/**
 * @brief The expected size of #SHADOW_REPORTED_JSON.
 *
 * Because all the format specifiers in #SHADOW_REPORTED_JSON include a length,
 * its full size is known at compile-time by pre-calculation. Users could refer to
 * the way how to calculate the actual length in #SHADOW_DESIRED_JSON_LENGTH.
 */
#define SHADOW_REPORTED_JSON_LENGTH    243

/**
 * @brief The maximum number of times to run the loop in this demo.
 *
 * @note The demo loop is attempted to re-run only if it fails in an iteration.
 * Once the demo loop succeeds in an iteration, the demo exits successfully.
 */
#ifndef SHADOW_MAX_DEMO_LOOP_COUNT
    #define SHADOW_MAX_DEMO_LOOP_COUNT    ( 3 )
#endif

/**
 * @brief Time in seconds to wait between retries of the demo loop if
 * demo loop fails.
 */
#define DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_S           ( 5 )

/**
 * @brief JSON key for response code that indicates the type of error in
 * the error document received on topic `/delete/rejected`.
 */
#define SHADOW_DELETE_REJECTED_ERROR_CODE_KEY           "code"

/**
 * @brief Length of #SHADOW_DELETE_REJECTED_ERROR_CODE_KEY
 */
#define SHADOW_DELETE_REJECTED_ERROR_CODE_KEY_LENGTH    ( ( uint16_t ) ( sizeof( SHADOW_DELETE_REJECTED_ERROR_CODE_KEY ) - 1 ) )

/*-----------------------------------------------------------*/

/**
 * @brief The flag to indicate the device current heap size changed.
 */
static bool stateChanged = false;

/**
 * @brief When we send an update to the device shadow, and if we care about
 * the response from cloud (accepted/rejected), remember the clientToken and
 * use it to match with the response.
 */
static char clientToken[128] = CLIENT_IDENTIFIER;

/**
 * @brief Indicator that an error occurred during the MQTT event callback. If an
 * error occurred during the MQTT event callback, then the demo has failed.
 */
static bool eventCallbackError = false;

/**
 * @brief Status of the response of Shadow delete operation from AWS IoT
 * message broker.
 */
static bool deleteResponseReceived = false;

/**
 * @brief Status of the Shadow delete operation.
 *
 * The Shadow delete status will be updated by the incoming publishes on the
 * MQTT topics for delete acknowledgement from AWS IoT message broker
 * (accepted/rejected). Shadow document is considered to be deleted if an
 * incoming publish is received on `/delete/accepted` topic or an incoming
 * publish is received on `/delete/rejected` topic with error code 404. Code 404
 * indicates that the Shadow document does not exist for the Thing yet.
 */
static bool shadowDeleted = false;

/*-----------------------------------------------------------*/

/**
 * @brief Status reported from the MQTT publish callback.
 */
static ResponseStatus_t responseStatus;

/**
 * @brief Buffer to hold the provisioned AWS IoT Thing name.
 */
static char thingName[ MAX_THING_NAME_LENGTH ];

/**
 * @brief Length of the AWS IoT Thing name.
 */
static size_t thingNameLength;

/**
 * @brief Buffer to hold responses received from the AWS IoT Fleet Provisioning
 * APIs. When the MQTT publish callback receives an expected Fleet Provisioning
 * accepted payload, it copies it into this buffer.
 */
static uint8_t payloadBuffer[ NETWORK_BUFFER_SIZE ];

/**
 * @brief Length of the payload stored in #payloadBuffer. This is set by the
 * MQTT publish callback when it copies a received payload into #payloadBuffer.
 */
static size_t payloadLength;

/*-----------------------------------------------------------*/

/**
 * @brief Callback to receive the incoming publish messages from the MQTT
 * broker. Sets responseStatus if an expected CreateCertificateFromCsr or
 * RegisterThing response is received, and copies the response into
 * responseBuffer if the response is an accepted one.
 *
 * @param[in] pPublishInfo Pointer to publish info of the incoming publish.
 * @param[in] packetIdentifier Packet identifier of the incoming publish.
 */
static void provisioningPublishCallback( MQTTPublishInfo_t * pPublishInfo,
                                         uint16_t packetIdentifier );

static void shadowCallback( MQTTPublishInfo_t * pPublishInfo,
                                         uint16_t packetIdentifier );

/**
 * @brief Run the MQTT process loop to get a response.
 */
static bool waitForResponse( void );

/**
 * @brief Subscribe to the CreateCertificateFromCsr accepted and rejected topics.
 */
static bool subscribeToCsrResponseTopics( void );

/**
 * @brief Unsubscribe from the CreateCertificateFromCsr accepted and rejected topics.
 */
static bool unsubscribeFromCsrResponseTopics( void );

/**
 * @brief Subscribe to the RegisterThing accepted and rejected topics.
 */
static bool subscribeToRegisterThingResponseTopics( void );

/**
 * @brief Unsubscribe from the RegisterThing accepted and rejected topics.
 */
static bool unsubscribeFromRegisterThingResponseTopics( void );

/*-----------------------------------------------------------*/

static void provisioningPublishCallback( MQTTPublishInfo_t * pPublishInfo,
                                         uint16_t packetIdentifier )
{
    FleetProvisioningStatus_t status;
    FleetProvisioningTopic_t api;
    const char * cborDump;

    /* Silence compiler warnings about unused variables. */
    ( void ) packetIdentifier;

    status = FleetProvisioning_MatchTopic( pPublishInfo->pTopicName,
                                           pPublishInfo->topicNameLength, &api );

    if( status != FleetProvisioningSuccess )
    {
        LogWarn( ( "Unexpected publish message received. Topic: %.*s.",
                   ( int ) pPublishInfo->topicNameLength,
                   ( const char * ) pPublishInfo->pTopicName ) );
    }
    else
    {
        if( api == FleetProvCborCreateCertFromCsrAccepted )
        {
            LogInfo( ( "Received accepted response from Fleet Provisioning CreateCertificateFromCsr API." ) );

            cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
            LogDebug( ( "Payload: %s", cborDump ) );
            free( ( void * ) cborDump );

            responseStatus = ResponseAccepted;

            /* Copy the payload from the MQTT library's buffer to #payloadBuffer. */
            ( void ) memcpy( ( void * ) payloadBuffer,
                             ( const void * ) pPublishInfo->pPayload,
                             ( size_t ) pPublishInfo->payloadLength );

            payloadLength = pPublishInfo->payloadLength;
        }
        else if( api == FleetProvCborCreateCertFromCsrRejected )
        {
            LogError( ( "Received rejected response from Fleet Provisioning CreateCertificateFromCsr API." ) );

            cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
            LogError( ( "Payload: %s", cborDump ) );
            free( ( void * ) cborDump );

            responseStatus = ResponseRejected;
        }
        else if( api == FleetProvCborRegisterThingAccepted )
        {
            LogInfo( ( "Received accepted response from Fleet Provisioning RegisterThing API." ) );

            cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
            LogDebug( ( "Payload: %s", cborDump ) );
            free( ( void * ) cborDump );

            responseStatus = ResponseAccepted;

            /* Copy the payload from the MQTT library's buffer to #payloadBuffer. */
            ( void ) memcpy( ( void * ) payloadBuffer,
                             ( const void * ) pPublishInfo->pPayload,
                             ( size_t ) pPublishInfo->payloadLength );

            payloadLength = pPublishInfo->payloadLength;
        }
        else if( api == FleetProvCborRegisterThingRejected )
        {
            LogError( ( "Received rejected response from Fleet Provisioning RegisterThing API." ) );

            cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
            LogError( ( "Payload: %s", cborDump ) );
            free( ( void * ) cborDump );

            responseStatus = ResponseRejected;
        }
        else
        {
            LogError( ( "Received message on unexpected Fleet Provisioning topic. Topic: %.*s.",
                        ( int ) pPublishInfo->topicNameLength,
                        ( const char * ) pPublishInfo->pTopicName ) );
        }
    }
}
/*-----------------------------------------------------------*/

static bool waitForResponse( void )
{
    bool status = false;

    responseStatus = ResponseNotReceived;

    /* responseStatus is updated from the MQTT publish callback. */
    ( void ) ProcessLoopWithTimeout();

    if( responseStatus == ResponseNotReceived )
    {
        LogError( ( "Timed out waiting for response." ) );
    }

    if( responseStatus == ResponseAccepted )
    {
        status = true;
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool subscribeToCsrResponseTopics( void )
{
    bool status;

    status = SubscribeToTopic( FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC,
                               FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH );

    if( status == false )
    {
        LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                    FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH,
                    FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC ) );
    }

    if( status == true )
    {
        status = SubscribeToTopic( FP_CBOR_CREATE_CERT_REJECTED_TOPIC,
                                   FP_CBOR_CREATE_CERT_REJECTED_LENGTH );

        if( status == false )
        {
            LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                        FP_CBOR_CREATE_CERT_REJECTED_LENGTH,
                        FP_CBOR_CREATE_CERT_REJECTED_TOPIC ) );
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool unsubscribeFromCsrResponseTopics( void )
{
    bool status;

    status = UnsubscribeFromTopic( FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC,
                                   FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH );

    if( status == false )
    {
        LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                    FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH,
                    FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC ) );
    }

    if( status == true )
    {
        status = UnsubscribeFromTopic( FP_CBOR_CREATE_CERT_REJECTED_TOPIC,
                                       FP_CBOR_CREATE_CERT_REJECTED_LENGTH );

        if( status == false )
        {
            LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                        FP_CBOR_CREATE_CERT_REJECTED_LENGTH,
                        FP_CBOR_CREATE_CERT_REJECTED_TOPIC ) );
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool subscribeToRegisterThingResponseTopics( void )
{
    bool status;

    status = SubscribeToTopic( FP_CBOR_REGISTER_ACCEPTED_TOPIC( PROVISIONING_TEMPLATE_NAME ),
                               FP_CBOR_REGISTER_ACCEPTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ) );

    if( status == false )
    {
        LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                    FP_CBOR_REGISTER_ACCEPTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                    FP_CBOR_REGISTER_ACCEPTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
    }

    if( status == true )
    {
        status = SubscribeToTopic( FP_CBOR_REGISTER_REJECTED_TOPIC( PROVISIONING_TEMPLATE_NAME ),
                                   FP_CBOR_REGISTER_REJECTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ) );

        if( status == false )
        {
            LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                        FP_CBOR_REGISTER_REJECTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                        FP_CBOR_REGISTER_REJECTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool unsubscribeFromRegisterThingResponseTopics( void )
{
    bool status;

    status = UnsubscribeFromTopic( FP_CBOR_REGISTER_ACCEPTED_TOPIC( PROVISIONING_TEMPLATE_NAME ),
                                   FP_CBOR_REGISTER_ACCEPTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ) );

    if( status == false )
    {
        LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                    FP_CBOR_REGISTER_ACCEPTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                    FP_CBOR_REGISTER_ACCEPTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
    }

    if( status == true )
    {
        status = UnsubscribeFromTopic( FP_CBOR_REGISTER_REJECTED_TOPIC( PROVISIONING_TEMPLATE_NAME ),
                                       FP_CBOR_REGISTER_REJECTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ) );

        if( status == false )
        {
            LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                        FP_CBOR_REGISTER_REJECTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                        FP_CBOR_REGISTER_REJECTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

void prepareJSONMessage(float temperature, float humidity, float moisture, uint8_t *buffer, size_t *length) {
    // Create the main JSON object
    cJSON *jsonObject = cJSON_CreateObject();

    struct timeval now;
    gettimeofday(&now, NULL);
    int64_t time_in_ms = (int64_t)now.tv_sec * 1000 + now.tv_usec / 1000;
    cJSON_AddNumberToObject(jsonObject, "timestamp", time_in_ms);
    
    cJSON_AddStringToObject(jsonObject, "device_id", CLIENT_IDENTIFIER);

    // Create a nested JSON object for data
    cJSON *dataObject = cJSON_CreateObject();
    cJSON_AddNumberToObject(dataObject, "temperature", temperature);
    cJSON_AddNumberToObject(dataObject, "humidity", humidity);
    cJSON_AddNumberToObject(dataObject, "moisture", moisture);

    // Add the data object to the main JSON object
    cJSON_AddItemToObject(jsonObject, "data", dataObject);

    // Print the JSON object to a string
    char *jsonString = cJSON_PrintUnformatted(jsonObject);

    // Copy the JSON string to the buffer and set the length
    *length = strlen(jsonString);
    memcpy(buffer, jsonString, *length);

    // Clean up
    cJSON_Delete(jsonObject);
    cJSON_free(jsonString); // Use cJSON_free to free the allocated string
}
/*-----------------------------------------------------------*/

void sendMessage(float temperature, float humidity, float moisture) {
    prepareJSONMessage(temperature, humidity, moisture, payloadBuffer, &payloadLength);
    bool status = false;

    status = PublishToTopic( MQTT_DATA_TOPIC,
                    MQTT_DATA_TOPIC_LENGTH,
                    ( char * ) payloadBuffer,
                    payloadLength );

    if( status == false )
    {
        LogError( ( "Failed to publish to topic: %.*s.",
                    MQTT_DATA_TOPIC_LENGTH,
                    MQTT_DATA_TOPIC ) );
    }

}

/* This example uses a single application task, which shows that how to use
 * the Fleet Provisioning library to generate and validate AWS IoT Fleet
 * Provisioning MQTT topics, and use the coreMQTT library to communicate with
 * the AWS IoT Fleet Provisioning APIs. */
int fleet_provisioning_main(CK_SESSION_HANDLE *p11Session)
{
    bool status = false;
    /* Buffer for holding the CSR. */
    char csr[ CSR_BUFFER_LENGTH ] = { 0 };
    size_t csrLength = 0;
    /* Buffer for holding received certificate until it is saved. */
    char certificate[ CERT_BUFFER_LENGTH ];
    size_t certificateLength;
    /* Buffer for holding the certificate ID. */
    char certificateId[ CERT_ID_BUFFER_LENGTH ];
    size_t certificateIdLength;
    /* Buffer for holding the certificate ownership token. */
    char ownershipToken[ OWNERSHIP_TOKEN_BUFFER_LENGTH ];
    size_t ownershipTokenLength;
    bool connectionEstablished = false;
    
    int demoRunCount = 0;
    CK_RV pkcs11ret = CKR_OK;

    do
    {
        /* Initialize the buffer lengths to their max lengths. */
        certificateLength = CERT_BUFFER_LENGTH;
        certificateIdLength = CERT_ID_BUFFER_LENGTH;
        ownershipTokenLength = OWNERSHIP_TOKEN_BUFFER_LENGTH;


        /* Insert the claim credentials into the PKCS #11 module */
        status = loadClaimCredentials( *p11Session,
                                        CLAIM_CERT_PATH,
                                        pkcs11configLABEL_CLAIM_CERTIFICATE,
                                        CLAIM_PRIVATE_KEY_PATH,
                                        pkcs11configLABEL_CLAIM_PRIVATE_KEY );

        if( status == false )
        {
            LogError( ( "Failed to provision PKCS #11 with claim credentials." ) );
        }
        

        /**** Connect to AWS IoT Core with provisioning claim credentials *****/

        /* We first use the claim credentials to connect to the broker. These
         * credentials should allow use of the RegisterThing API and one of the
         * CreateCertificatefromCsr or CreateKeysAndCertificate.
         * In this demo we use CreateCertificatefromCsr. */

        if( status == true )
        {
            /* Attempts to connect to the AWS IoT MQTT broker. If the
             * connection fails, retries after a timeout. Timeout value will
             * exponentially increase until maximum attempts are reached. */
            LogInfo( ( "Establishing MQTT session with claim certificate..." ) );
            status = EstablishMqttSession( provisioningPublishCallback,
                                           *p11Session,
                                           pkcs11configLABEL_CLAIM_CERTIFICATE,
                                           pkcs11configLABEL_CLAIM_PRIVATE_KEY );

            if( status == false )
            {
                LogError( ( "Failed to establish MQTT session." ) );
            }
            else
            {
                LogInfo( ( "Established connection with claim credentials." ) );
                connectionEstablished = true;
            }
        }

        /**** Call the CreateCertificateFromCsr API ***************************/

        /* We use the CreateCertificatefromCsr API to obtain a client certificate
         * for a key on the device by means of sending a certificate signing
         * request (CSR). */
        if( status == true )
        {
            /* Subscribe to the CreateCertificateFromCsr accepted and rejected
             * topics. In this demo we use CBOR encoding for the payloads,
             * so we use the CBOR variants of the topics. */
            status = subscribeToCsrResponseTopics();
        }

        if( status == true )
        {
            /* Create a new key and CSR. */
            status = generateKeyAndCsr( *p11Session,
                                        pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                        pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                        csr,
                                        CSR_BUFFER_LENGTH,
                                        &csrLength );
        }

        if( status == true )
        {
            /* Create the request payload containing the CSR to publish to the
             * CreateCertificateFromCsr APIs. */
            status = generateCsrRequest( payloadBuffer,
                                         NETWORK_BUFFER_SIZE,
                                         csr,
                                         csrLength,
                                         &payloadLength );
        }

        if( status == true )
        {
            /* Publish the CSR to the CreateCertificatefromCsr API. */
            PublishToTopic( FP_CBOR_CREATE_CERT_PUBLISH_TOPIC,
                            FP_CBOR_CREATE_CERT_PUBLISH_LENGTH,
                            ( char * ) payloadBuffer,
                            payloadLength );

            if( status == false )
            {
                LogError( ( "Failed to publish to fleet provisioning topic: %.*s.",
                            FP_CBOR_CREATE_CERT_PUBLISH_LENGTH,
                            FP_CBOR_CREATE_CERT_PUBLISH_TOPIC ) );
            }
        }

        if( status == true )
        {
            /* Get the response to the CreateCertificatefromCsr request. */
            status = waitForResponse();
        }

        if( status == true )
        {
            /* From the response, extract the certificate, certificate ID, and
             * certificate ownership token. */
            status = parseCsrResponse( payloadBuffer,
                                       payloadLength,
                                       certificate,
                                       &certificateLength,
                                       certificateId,
                                       &certificateIdLength,
                                       ownershipToken,
                                       &ownershipTokenLength );

            if( status == true )
            {
                LogInfo( ( "Received certificate with Id: %.*s", ( int ) certificateIdLength, certificateId ) );
            }
        }

        if( status == true )
        {
            /* Save the certificate into PKCS #11. */
            status = loadCertificate( *p11Session,
                                      certificate,
                                      pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                      certificateLength );
        }

        if( status == true )
        {
            /* Unsubscribe from the CreateCertificateFromCsr topics. */
            status = unsubscribeFromCsrResponseTopics();
        }

        /**** Call the RegisterThing API **************************************/

        /* We then use the RegisterThing API to activate the received certificate,
         * provision AWS IoT resources according to the provisioning template, and
         * receive device configuration. */
        if( status == true )
        {
            /* Create the request payload to publish to the RegisterThing API. */
            status = generateRegisterThingRequest( payloadBuffer,
                                                   NETWORK_BUFFER_SIZE,
                                                   ownershipToken,
                                                   ownershipTokenLength,
                                                   DEVICE_SERIAL_NUMBER,
                                                   DEVICE_SERIAL_NUMBER_LENGTH,
                                                   &payloadLength );
        }

        if( status == true )
        {
            /* Subscribe to the RegisterThing response topics. */
            status = subscribeToRegisterThingResponseTopics();
        }

        if( status == true )
        {
            /* Publish the RegisterThing request. */
            PublishToTopic( FP_CBOR_REGISTER_PUBLISH_TOPIC( PROVISIONING_TEMPLATE_NAME ),
                            FP_CBOR_REGISTER_PUBLISH_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                            ( char * ) payloadBuffer,
                            payloadLength );

            if( status == false )
            {
                LogError( ( "Failed to publish to fleet provisioning topic: %.*s.",
                            FP_CBOR_REGISTER_PUBLISH_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                            FP_CBOR_REGISTER_PUBLISH_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
            }
        }

        if( status == true )
        {
            /* Get the response to the RegisterThing request. */
            status = waitForResponse();
        }

        if( status == true )
        {
            /* Extract the Thing name from the response. */
            thingNameLength = MAX_THING_NAME_LENGTH;
            status = parseRegisterThingResponse( payloadBuffer,
                                                 payloadLength,
                                                 thingName,
                                                 &thingNameLength );

            if( status == true )
            {
                LogInfo( ( "Received AWS IoT Thing name: %.*s", ( int ) thingNameLength, thingName ) );
            }
        }

        if( status == true )
        {
            /* Unsubscribe from the RegisterThing topics. */
            unsubscribeFromRegisterThingResponseTopics();
        }

        /**** Disconnect from AWS IoT Core ************************************/

        /* As we have completed the provisioning workflow, we disconnect from
         * the connection using the provisioning claim credentials. We will
         * establish a new MQTT connection with the newly provisioned
         * credentials. */
        if( connectionEstablished == true )
        {
            DisconnectMqttSession();
            connectionEstablished = false;
        }

        /**** Connect to AWS IoT Core with provisioned certificate ************/

        if( status == true )
        {
            LogInfo( ( "Establishing MQTT session with provisioned certificate..." ) );
            status = EstablishMqttSession( shadowCallback,
                                           *p11Session,
                                           pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                           pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS );

            if( status != true )
            {
                LogError( ( "Failed to establish MQTT session with provisioned "
                            "credentials. Verify on your AWS account that the "
                            "new certificate is active and has an attached IoT "
                            "Policy that allows the \"iot:Connect\" action." ) );
            }
            else
            {
                LogInfo( ( "Sucessfully established connection with provisioned credentials." ) );
                connectionEstablished = true;

            }
        }

        /**** Finish **********************************************************/

        if( connectionEstablished == true )
        {
            /* Close the connection. */
            //DisconnectMqttSession();
            //connectionEstablished = false;
        }

        /**** Retry in case of failure ****************************************/

        /* Increment the demo run count. */
        demoRunCount++;

        if( status == true )
        {
            LogInfo( ( "Iteration %d is successful.", demoRunCount ) );
        }
        /* Attempt to retry a failed iteration of demo for up to #FLEET_PROV_MAX_DEMO_LOOP_COUNT times. */
        else if( demoRunCount < FLEET_PROV_MAX_DEMO_LOOP_COUNT )
        {
            LogWarn( ( "Iteration %d failed. Retrying...", demoRunCount ) );
            sleep( DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_SECONDS );
        }
        /* Failed all #FLEET_PROV_MAX_DEMO_LOOP_COUNT demo iterations. */
        else
        {
            LogError( ( "All %d iterations failed.", FLEET_PROV_MAX_DEMO_LOOP_COUNT ) );
            break;
        }
    } while( status != true );

    return ( status == true ) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/*-----------------------------------------------------------*/

/*-----------------------------------------------------------*/


static const char* get_random_color_string() {
    const char* colors[] = {"RED", "GREEN", "BLUE", "YELLOW", "PINK", "WHITE"};
    int num_colors = sizeof(colors) / sizeof(colors[0]);
    int random_index = rand() % num_colors;
    return colors[random_index];
}

static void deleteRejectedHandler( MQTTPublishInfo_t * pPublishInfo )
{
    JSONStatus_t result = JSONSuccess;
    char * pOutValue = NULL;
    uint32_t outValueLength = 0U;
    long errorCode = 0L;

    assert( pPublishInfo != NULL );
    assert( pPublishInfo->pPayload != NULL );

    LogInfo( ( "/delete/rejected json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );

    /* The payload will look similar to this:
     * {
     *    "code": error-code,
     *    "message": "error-message",
     *    "timestamp": timestamp,
     *    "clientToken": "token"
     * }
     */

    /* Make sure the payload is a valid json document. */
    result = JSON_Validate( ( const char * ) pPublishInfo->pPayload,
                            pPublishInfo->payloadLength );

    if( result == JSONSuccess )
    {
        /* Then we start to get the version value by JSON keyword "version". */
        result = JSON_Search( ( char * ) pPublishInfo->pPayload,
                              pPublishInfo->payloadLength,
                              SHADOW_DELETE_REJECTED_ERROR_CODE_KEY,
                              SHADOW_DELETE_REJECTED_ERROR_CODE_KEY_LENGTH,
                              &pOutValue,
                              ( size_t * ) &outValueLength );
    }
    else
    {
        LogError( ( "The json document is invalid!!" ) );
    }

    if( result == JSONSuccess )
    {
        LogInfo( ( "Error code is: %.*s.",
                   (int) outValueLength,
                   pOutValue ) );

        /* Convert the extracted value to an unsigned integer value. */
        errorCode = strtoul( pOutValue, NULL, 10 );
    }
    else
    {
        LogError( ( "No error code in json document!!" ) );
    }

    LogInfo( ( "Error code:%ld.", errorCode ) );

    /* Mark Shadow delete operation as a success if error code is 404. */
    if( errorCode == 404UL )
    {
        shadowDeleted = true;
    }
}

/*-----------------------------------------------------------*/

static void updateDeltaHandler( MQTTPublishInfo_t * pPublishInfo )
{
    static uint32_t currentVersion = 0; /* Remember the latestVersion # we've ever received */
    uint32_t version = 0U;
    const char* newColor;
    char * outValue = NULL;
    uint32_t outValueLength = 0U;
    JSONStatus_t result = JSONSuccess;

    assert( pPublishInfo != NULL );
    assert( pPublishInfo->pPayload != NULL );

    LogInfo( ( "/update/delta json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );

    /* The payload will look similar to this:
     * {
     *      "version": 12,
     *      "timestamp": 1595437367,
     *      "state": {
     *          "heap": 1,
     *          "color": "GREEN"
     *      },
     *      "metadata": {
     *          "heap": {
     *          "timestamp": 1595437367
     *          }
     *      },
     *      "clientToken": "388062"
     *  }
     */

    /* Make sure the payload is a valid json document. */
    result = JSON_Validate( ( const char * ) pPublishInfo->pPayload,
                            pPublishInfo->payloadLength );

    if( result == JSONSuccess )
    {
        /* Then we start to get the version value by JSON keyword "version". */
        result = JSON_Search( ( char * ) pPublishInfo->pPayload,
                              pPublishInfo->payloadLength,
                              "version",
                              sizeof( "version" ) - 1,
                              &outValue,
                              ( size_t * ) &outValueLength );
    }
    else
    {
        LogError( ( "The json document is invalid!!" ) );
        eventCallbackError = true;
    }

    if( result == JSONSuccess )
    {
        LogInfo( ( "version: %.*s",
                   (int) outValueLength,
                   outValue ) );

        /* Convert the extracted value to an unsigned integer value. */
        version = ( uint32_t ) strtoul( outValue, NULL, 10 );
    }
    else
    {
        LogError( ( "No version in json document!!" ) );
        eventCallbackError = true;
    }

    LogInfo( ( "version:%"PRIu32", currentVersion:%"PRIu32" \r\n", version, currentVersion ) );

    /* When the version is much newer than the on we retained, that means the heap
     * state is valid for us. */
    if( version > currentVersion )
    {
        /* Set to received version as the current version. */
        currentVersion = version;

        /* Get heap state from json documents. */
        result = JSON_Search( ( char * ) pPublishInfo->pPayload,
                              pPublishInfo->payloadLength,
                              "state.color",
                              sizeof( "state.color" ) - 1,
                              &outValue,
                              ( size_t * ) &outValueLength );
    }
    else
    {
        /* In this demo, we discard the incoming message
         * if the version number is not newer than the latest
         * that we've received before. Your application may use a
         * different approach.
         */
        LogWarn( ( "The received version is smaller than current one!!" ) );
    }

    if( result == JSONSuccess )
    {
        /* Convert the heap state value to an unsigned integer value. */
        newColor = ( const char* ) strtoul( outValue, NULL, 10 );

        LogInfo( ( "The new color state newColor:%s, currentColor:%s \r\n",
                   newColor, currentColor ) );

        if( strcmp(newColor, currentColor) != 0 )
        {
            /* The received heap state is different from the one we retained before, so we switch them
             * and set the flag. */
            strcpy(currentColor, newColor);

            /* State change will be handled in main(), where we will publish a "reported"
             * state to the device shadow. We do not do it here because we are inside of
             * a callback from the MQTT library, so that we don't re-enter
             * the MQTT library. */
            stateChanged = true;
        }
    }
    else
    {
        LogError( ( "No heap in json document!!" ) );
        eventCallbackError = true;
    }
}

/*-----------------------------------------------------------*/

static void updateAcceptedHandler( MQTTPublishInfo_t * pPublishInfo )
{
    char * outValue = NULL;
    uint32_t outValueLength = 0U;
    char receivedToken[128];
    JSONStatus_t result = JSONSuccess;

    assert( pPublishInfo != NULL );
    assert( pPublishInfo->pPayload != NULL );

    LogInfo( ( "/update/accepted json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );

    /* Handle the reported state with state change in /update/accepted topic.
     * Thus we will retrieve the client token from the json document to see if
     * it's the same one we sent with reported state on the /update topic.
     * The payload will look similar to this:
     *  {
     *      "state": {
     *          "reported": {
     *          "heap": 1,
     *          "color": "GREEN"
     *          }
     *      },
     *      "metadata": {
     *          "reported": {
     *          "heap": {
     *              "timestamp": 1596573647
     *          }
     *          }
     *      },
     *      "version": 14698,
     *      "timestamp": 1596573647,
     *      "clientToken": "022485"
     *  }
     */

    /* Make sure the payload is a valid json document. */
    result = JSON_Validate( ( const char * ) pPublishInfo->pPayload,
                            pPublishInfo->payloadLength );

    if( result == JSONSuccess )
    {
        /* Get clientToken from json documents. */
        result = JSON_Search( ( char * ) pPublishInfo->pPayload,
                              pPublishInfo->payloadLength,
                              "clientToken",
                              sizeof( "clientToken" ) - 1,
                              &outValue,
                              ( size_t * ) &outValueLength );
    }
    else
    {
        LogError( ( "Invalid json documents !!" ) );
        eventCallbackError = true;
    }

    if( result == JSONSuccess )
    {
        LogInfo( ( "clientToken: %.*s", (int) outValueLength,
                   outValue ) );

        /* Convert the code to an unsigned integer value. */
        memcpy(receivedToken, outValue, outValueLength);

        LogInfo( ( "receivedToken:%s, clientToken:%s \r\n", receivedToken, clientToken ) );

        /* If the clientToken in this update/accepted message matches the one we
         * published before, it means the device shadow has accepted our latest
         * reported state. We are done. */
        if( strcmp (receivedToken, clientToken) == 0)
        {
            LogInfo( ( "Received response from the device shadow. Previously published "
                       "update with clientToken=%s has been accepted. ", clientToken ) );
        }
        else
        {
            LogWarn( ( "The received clientToken=%s is not identical with the one=%s we sent "
                       , receivedToken, clientToken ) );
        }
    }
    else
    {
        LogError( ( "No clientToken in json document!!" ) );
        eventCallbackError = true;
    }
}

/*-----------------------------------------------------------*/

/* This is the callback function invoked by the MQTT stack when it receives
 * incoming messages. This function demonstrates how to use the Shadow_MatchTopicString
 * function to determine whether the incoming message is a device shadow message
 * or not. If it is, it handles the message depending on the message type.
 */
static void shadowCallback( MQTTPublishInfo_t * pPublishInfo,
                            uint16_t packetIdentifier )
{
    ShadowMessageType_t messageType = ShadowMessageTypeMaxNum;
    const char * pThingName = NULL;
    uint8_t thingNameLength = 0U;
    const char * pShadowName = NULL;
    uint8_t shadowNameLength = 0U;

    (void)packetIdentifier;

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */

    LogInfo( ( "pPublishInfo->pTopicName:%s.", pPublishInfo->pTopicName ) );

    /* Let the Device Shadow library tell us whether this is a device shadow message. */
    if( SHADOW_SUCCESS == Shadow_MatchTopicString( pPublishInfo->pTopicName,
                                                    pPublishInfo->topicNameLength,
                                                    &messageType,
                                                    &pThingName,
                                                    &thingNameLength,
                                                    &pShadowName,
                                                    &shadowNameLength ) )
    {
        /* Upon successful return, the messageType has been filled in. */
        if( messageType == ShadowMessageTypeUpdateDelta )
        {
            /* Handler function to process payload. */
            updateDeltaHandler( pPublishInfo );
        }
        else if( messageType == ShadowMessageTypeUpdateAccepted )
        {
            /* Handler function to process payload. */
            updateAcceptedHandler( pPublishInfo );

        }
        else if( messageType == ShadowMessageTypeUpdateDocuments )
        {
            LogInfo( ( "/update/documents json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );
        }
        else if( messageType == ShadowMessageTypeUpdateRejected )
        {
            LogInfo( ( "/update/rejected json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );
        }
        else if( messageType == ShadowMessageTypeDeleteAccepted )
        {
            LogInfo( ( "Received an MQTT incoming publish on /delete/accepted topic." ) );
            shadowDeleted = true;
            deleteResponseReceived = true;
        }
        else if( messageType == ShadowMessageTypeDeleteRejected )
        {
            /* Handler function to process payload. */
            deleteRejectedHandler( pPublishInfo );
            deleteResponseReceived = true;
        }
        else
        {
            LogInfo( ( "Other message type:%d !!", messageType ) );
        }
    }
    else
    {
        LogError( ( "Shadow_MatchTopicString parse failed:%s !!", ( const char * ) pPublishInfo->pTopicName ) );
        eventCallbackError = true;
    }
}

/*-----------------------------------------------------------*/

/**
 * @brief Entry point of shadow demo.
 *
 * This main function demonstrates how to use the macros provided by the
 * Device Shadow library to assemble strings for the MQTT topics defined
 * by AWS IoT Device Shadow. Named shadow topic strings differ from unnamed
 * ("Classic") topic strings as indicated by the tokens within square brackets.
 *
 * The main function uses these macros for topics to subscribe to:
 * - SHADOW_TOPIC_STR_UPDATE_DELTA for "$aws/things/thingName/shadow[/name/shadowname]/update/delta"
 * - SHADOW_TOPIC_STR_UPDATE_ACC for "$aws/things/thingName/shadow[/name/shadowname]/update/accepted"
 * - SHADOW_TOPIC_STR_UPDATE_REJ for "$aws/things/thingName/shadow[/name/shadowname]/update/rejected"
 *
 * It also uses these macros for topics to publish to:
 * - SHADOW_TOPIC_STR_DELETE for "$aws/things/thingName/shadow[/name/shadowname]/delete"
 * - SHADOW_TOPIC_STR_UPDATE for "$aws/things/thingName/shadow[/name/shadowname]/update"
 *
 * The helper functions this demo uses for MQTT operations have internal
 * loops to process incoming messages. Those are not the focus of this demo
 * and therefore, are placed in a separate file shadow_demo_helpers.c.
 */

const char * device_shadow_main(void)
{
    int status = false;
    int demoRunCount = 0;

    /* A buffer containing the update document. It has static duration to prevent
     * it from being placed on the call stack. */
    static char updateDocument[ SHADOW_REPORTED_JSON_LENGTH + 1 ] = { 0 };

    do
    {

        /* Reset the shadow delete status flags. */
        deleteResponseReceived = false;
        shadowDeleted = false;

        LogInfo( ( "First of all, try to delete any Shadow document in the cloud." ) );

        /* First of all, try to delete any Shadow document in the cloud.
            * Try to subscribe to `/delete/accepted` and `/delete/rejected` topics. */
        status = SubscribeToTopic( SHADOW_TOPIC_STR_DELETE_ACC( THING_NAME, SHADOW_NAME ),
                                             SHADOW_TOPIC_LEN_DELETE_ACC( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
        
        if( status == true )
        {
            /* Try to subscribe to `/delete/rejected` topic. */
            LogInfo( ( "Try to subscribe to `/delete/accepted` and `/delete/rejected` topics." ) );
            status = SubscribeToTopic( SHADOW_TOPIC_STR_DELETE_REJ( THING_NAME, SHADOW_NAME ),
                                                 SHADOW_TOPIC_LEN_DELETE_REJ( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
        }

        if( status == true )
        {
            /* Publish to Shadow `delete` topic to attempt to delete the
                * Shadow document if exists. */
            LogInfo( ( "Publish to Shadow `delete` topic to attempt to delete the shadow doc." ) );
            LogInfo( ( "THING_NAME: %s", THING_NAME ) );
            status = PublishToTopicQoS1( SHADOW_TOPIC_STR_DELETE( THING_NAME, SHADOW_NAME ),
                                               SHADOW_TOPIC_LEN_DELETE( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ),
                                               updateDocument,
                                               0U );
        }

        /* Unsubscribe from the `/delete/accepted` and 'delete/rejected` topics.*/
        if( status == true )
        {
            LogInfo( ( "Unsubscribe from the `/delete/accepted` and 'delete/rejected` topics." ) );
            status = UnsubscribeFromTopic( SHADOW_TOPIC_STR_DELETE_ACC( THING_NAME, SHADOW_NAME ),
                                                     SHADOW_TOPIC_LEN_DELETE_ACC( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
        }

        if( status == true )
        {
            status = UnsubscribeFromTopic( SHADOW_TOPIC_STR_DELETE_REJ( THING_NAME, SHADOW_NAME ),
                                                     SHADOW_TOPIC_LEN_DELETE_REJ( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
        }

        /* Check if an incoming publish on `/delete/accepted` or `/delete/rejected`
         * topics. If a response is not received, mark the demo execution as a failure.*/
        if( ( status == true ) && ( deleteResponseReceived != true ) )
        {
            LogError( ( "Failed to receive a response for Shadow delete." ) );
            //status = false;
            shadowDeleted = true;
        }

        /* Check if Shadow document delete was successful. A delete can be
             * successful in cases listed below.
             *  1. If an incoming publish is received on `/delete/accepted` topic.
             *  2. If an incoming publish is received on `/delete/rejected` topic
             *     with an error code 404. This indicates that a delete was
             *     attempted when a Shadow document is not available for the
             *     Thing. */
        if( status == true )
        {
            if( shadowDeleted == false )
            {
                LogError( ( "Shadow delete operation failed." ) );
                status = false;
            }
        }

        /* Successfully connect to MQTT broker, the next step is
            * to subscribe shadow topics. */
        if( status == true )
        {
            status = SubscribeToTopic( SHADOW_TOPIC_STR_UPDATE_DELTA( THING_NAME, SHADOW_NAME ),
                                                 SHADOW_TOPIC_LEN_UPDATE_DELTA( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
        }

        if( status == true )
        {
            status = SubscribeToTopic( SHADOW_TOPIC_STR_UPDATE_ACC( THING_NAME, SHADOW_NAME ),
                                                 SHADOW_TOPIC_LEN_UPDATE_ACC( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
        }

        if( status == true )
        {
            status = SubscribeToTopic( SHADOW_TOPIC_STR_UPDATE_REJ( THING_NAME, SHADOW_NAME ),
                                                 SHADOW_TOPIC_LEN_UPDATE_REJ( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
        }

            /* This demo uses a constant #THING_NAME and #SHADOW_NAME known at compile time therefore
             * we can use macros to assemble shadow topic strings.
             * If the thing name or shadow name is only known at run time, then we could use the API
             * #Shadow_AssembleTopicString to assemble shadow topic strings, here is the example for /update/delta:
             *
             * For /update/delta:
             *
             * #define SHADOW_TOPIC_MAX_LENGTH  (256U)
             *
             * ShadowStatus_t shadowStatus = SHADOW_SUCCESS;
             * char topicBuffer[ SHADOW_TOPIC_MAX_LENGTH ] = { 0 };
             * uint16_t bufferSize = SHADOW_TOPIC_MAX_LENGTH;
             * uint16_t outLength = 0;
             * const char thingName[] = { "TestThingName" };
             * uint16_t thingNameLength  = ( sizeof( thingName ) - 1U );
             * const char shadowName[] = { "TestShadowName" };
             * uint16_t shadowNameLength  = ( sizeof( shadowName ) - 1U );
             *
             * shadowStatus = Shadow_AssembleTopicString( ShadowTopicStringTypeUpdateDelta,
             *                                            thingName,
             *                                            thingNameLength,
             *                                            shadowName,
             *                                            shadowNameLength,
             *                                            & ( topicBuffer[ 0 ] ),
             *                                            bufferSize,
             *                                            & outLength );
             */

        /* Then we publish a desired state to the /update topic. Since we've deleted
            * the device shadow at the beginning of the demo, this will cause a delta message
            * to be published, which we have subscribed to.
            * In many real applications, the desired state is not published by
            * the device itself. But for the purpose of making this demo self-contained,
            * we publish one here so that we can receive a delta message later.
            */
        if( status == true )
        {
            /* desired color . */
            LogInfo( ( "Send desired color." ) );

            ( void ) memset( updateDocument,
                                0x00,
                                sizeof( updateDocument ) );

            /* Keep the client token in global variable used to compare if
                * the same token in /update/accepted. */
            const char* randomColor = get_random_color_string();
            strncpy(currentColor, randomColor, sizeof(currentColor) - 1);
            currentColor[sizeof(currentColor) - 1] = '\0';

            snprintf( updateDocument,
                        SHADOW_DESIRED_JSON_LENGTH + 1,
                        SHADOW_DESIRED_JSON,
                        currentColor,
                        clientToken );

            status = PublishToTopicQoS1( SHADOW_TOPIC_STR_UPDATE( THING_NAME, SHADOW_NAME ),
                                            SHADOW_TOPIC_LEN_UPDATE( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ),
                                            updateDocument,
                                            ( SHADOW_DESIRED_JSON_LENGTH + 1 ) );
        }

        if( status == true )
        {
            /* Note that PublishToTopic already called MQTT_ProcessLoop,
                * therefore responses may have been received and the eventCallback
                * may have been called, which may have changed the stateChanged flag.
                * Check if the state change flag has been modified or not. If it's modified,
                * then we publish reported state to update topic.
                */
            if( stateChanged == true )
            {
                /* Report the latest power state back to device shadow. */
                ( void ) memset( updateDocument,
                                    0x00,
                                    sizeof( updateDocument ) );

                /* Keep the client token in global variable used to compare if
                    * the same token in /update/accepted. */

                snprintf( updateDocument,
                            SHADOW_REPORTED_JSON_LENGTH + 1,
                            SHADOW_REPORTED_JSON,
                            currentColor,
                            clientToken );

                status = PublishToTopicQoS1( SHADOW_TOPIC_STR_UPDATE( THING_NAME, SHADOW_NAME ),
                                                SHADOW_TOPIC_LEN_UPDATE( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ),
                                                updateDocument,
                                                ( SHADOW_REPORTED_JSON_LENGTH + 1 ) );
            }
                else
            {
                LogInfo( ( "No change from /update/delta." ) );
            }
        }

        /* This demo performs only Device Shadow operations. If matching the Shadow
         * topic fails or there are failures in parsing the received JSON document,
         * then this demo was not successful. */
        if( eventCallbackError == true )
        {
            status = false;
        }

        /* Increment the demo run count. */
        demoRunCount++;

        if( status == true )
        {
            LogInfo( ( "Shadow iteration %d is successful.", demoRunCount ) );
        }
        /* Attempt to retry a failed iteration of demo for up to #SHADOW_MAX_DEMO_LOOP_COUNT times. */
        else if( demoRunCount < SHADOW_MAX_DEMO_LOOP_COUNT )
        {
            LogWarn( ( "Shadow iteration %d failed. Retrying...", demoRunCount ) );
            sleep( DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_S );
        }
        /* Failed all #SHADOW_MAX_DEMO_LOOP_COUNT demo iterations. */
        else
        {
            LogError( ( "All %d shadow iterations failed.", SHADOW_MAX_DEMO_LOOP_COUNT ) );
            break;
        }
    } while( status != true );

    LogInfo(("This is my currentColor, sending further: %s", currentColor));

    return currentColor;
}

/*-----------------------------------------------------------*/