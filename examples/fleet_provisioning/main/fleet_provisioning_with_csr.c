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

/* OTA Library include. */
#include "ota.h"
#include "ota_config.h"

/* OTA Library Interface include. */
#include "ota_os_freertos.h"
#include "ota_mqtt_interface.h"
#include "ota_pal.h"

/* Include firmware version struct definition. */
#include "ota_appversion32.h"
#include "esp_pthread.h"

/* OpenSSL sockets transport implementation. */
#include "network_transport.h"

/* Clock for timer. */
#include "clock.h"

#include <pthread.h>
#include "semaphore.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "mqtt_subscription_manager.h"

/*Include backoff algorithm header for retry logic.*/
#include "backoff_algorithm.h"

/**
 * @brief The common prefix for all OTA topics.
 */
#define OTA_TOPIC_PREFIX    "$aws/things/+/"

/**
 * @brief The string used for jobs topics.
 */
#define OTA_TOPIC_JOBS      "jobs"

/**
 * @brief The string used for streaming service topics.
 */
#define OTA_TOPIC_STREAM    "streams"

/**
 * @brief Period for demo loop sleep in milliseconds.
 */
#define OTA_EXAMPLE_LOOP_SLEEP_PERIOD_MS    ( 5U )

/**
 * @brief Size of the network buffer to receive the MQTT message.
 *
 * The largest message size is data size from the AWS IoT streaming service,
 * otaconfigFILE_BLOCK_SIZE + extra for headers.
 */

#define OTA_NETWORK_BUFFER_SIZE                  ( otaconfigFILE_BLOCK_SIZE + 128 )

/**
 * @brief The delay used in the main OTA Demo task loop to periodically output the OTA
 * statistics like number of packets received, dropped, processed and queued per connection.
 */
#define OTA_EXAMPLE_TASK_DELAY_MS                ( 1000U )

/**
 * @brief The timeout for waiting for the agent to get suspended after closing the
 * connection.
 */
#define OTA_SUSPEND_TIMEOUT_MS                   ( 5000U )

/**
 * @brief The timeout for waiting before exiting the OTA demo.
 */
#define OTA_DEMO_EXIT_TIMEOUT_MS                 ( 3000U )

/**
 * @brief The maximum size of the file paths used in the demo.
 */
#define OTA_MAX_FILE_PATH_SIZE                   ( 260U )

/**
 * @brief The maximum size of the stream name required for downloading update file
 * from streaming service.
 */
#define OTA_MAX_STREAM_NAME_SIZE                 ( 128U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying connection to server.
 */
#define CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS    ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for connection retry attempts.
 */
#define CONNECTION_RETRY_BACKOFF_BASE_MS         ( 500U )

/**
 * @brief Maximum number or retries to publish a message in case of failures.
 */
#define MQTT_PUBLISH_RETRY_MAX_ATTEMPS      ( 3U )

/**
 * @brief Struct for firmware version.
 */
const AppVersion32_t appFirmwareVersion =
{
    .u.x.major = APP_VERSION_MAJOR,
    .u.x.minor = APP_VERSION_MINOR,
    .u.x.build = APP_VERSION_BUILD,
};

/**
 * @brief Semaphore for synchronizing buffer operations.
 */
// static osi_sem_t bufferSemaphore;
static osi_sem_t bufferSemaphore;

/**
 * @brief Semaphore for synchronizing wait for ack.
 */
static osi_sem_t ackSemaphore;

extern const char pcAwsCodeSigningCertPem[] asm("_binary_codesign_crt_start");

/**
 * @brief Mutex for synchronizing coreMQTT API calls.
 */
static pthread_mutex_t mqttMutex;

/**
 * @brief MQTT connection context used in this demo.
 */
static MQTTContext_t mqttContext;

/**
 * @brief Enum for type of OTA job messages received.
 */
typedef enum jobMessageType
{
    jobMessageTypeNextGetAccepted = 0,
    jobMessageTypeNextNotify,
    jobMessageTypeMax
} jobMessageType_t;

/**
 * @brief The network buffer must remain valid when OTA library task is running.
 */
static uint8_t otaNetworkBuffer[ OTA_NETWORK_BUFFER_SIZE ];

/**
 * @brief Update File path buffer.
 */
uint8_t updateFilePath[ OTA_MAX_FILE_PATH_SIZE ];

/**
 * @brief Certificate File path buffer.
 */
uint8_t certFilePath[ OTA_MAX_FILE_PATH_SIZE ];

/**
 * @brief Stream name buffer.
 */
uint8_t streamName[ OTA_MAX_STREAM_NAME_SIZE ];

/**
 * @brief Decode memory.
 */
uint8_t decodeMem[ otaconfigFILE_BLOCK_SIZE ];

/**
 * @brief Bitmap memory.
 */
uint8_t bitmap[ OTA_MAX_BLOCK_BITMAP_SIZE ];

/**
 * @brief Event buffer.
 */
static OtaEventData_t eventBuffer[ otaconfigMAX_NUM_OTA_DATA_BUFFERS ];

/**
 * @brief The buffer passed to the OTA Agent from application while initializing.
 */
static OtaAppBuffer_t otaBuffer =
{
    .pUpdateFilePath    = updateFilePath,
    .updateFilePathsize = OTA_MAX_FILE_PATH_SIZE,
    .pCertFilePath      = certFilePath,
    .certFilePathSize   = OTA_MAX_FILE_PATH_SIZE,
    .pStreamName        = streamName,
    .streamNameSize     = OTA_MAX_STREAM_NAME_SIZE,
    .pDecodeMemory      = decodeMem,
    .decodeMemorySize   = otaconfigFILE_BLOCK_SIZE,
    .pFileBitmap        = bitmap,
    .fileBitmapSize     = OTA_MAX_BLOCK_BITMAP_SIZE
};

/**
 * @brief Callback registered with the OTA library that notifies the OTA agent
 * of an incoming PUBLISH containing a job document.
 *
 * @param[in] pContext MQTT context which stores the connection.
 * @param[in] pPublishInfo MQTT packet information which stores details of the
 * job document.
 */
static void mqttJobCallback( MQTTContext_t * pContext,
                             MQTTPublishInfo_t * pPublishInfo );

/**
 * @brief Callback that notifies the OTA library when a data block is received.
 *
 * @param[in] pContext MQTT context which stores the connection.
 * @param[in] pPublishInfo MQTT packet that stores the information of the file block.
 */
static void mqttDataCallback( MQTTContext_t * pContext,
                              MQTTPublishInfo_t * pPublishInfo );

static SubscriptionManagerCallback_t otaMessageCallback[] = { mqttJobCallback, mqttDataCallback };

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

void otaEventBufferFree( OtaEventData_t * const pxBuffer )
{
    if( osi_sem_take( &bufferSemaphore, 0 ) == 0 )
    {
        pxBuffer->bufferUsed = false;
        ( void ) osi_sem_give( &bufferSemaphore );
    }
    else
    {
        LogError( ( "Failed to get buffer semaphore: "
                    ",errno=%s",
                    strerror( errno ) ) );
    }
}
/*-----------------------------------------------------------*/

static uint32_t generateRandomNumber()
{
    return( rand() );
}

/*-----------------------------------------------------------*/

static void otaAppCallback( OtaJobEvent_t event,
                            void * pData )
{
    OtaErr_t err = OtaErrUninitialized;
    int ret;

    switch( event )
    {
        case OtaJobEventActivate:
            LogInfo( ( "Received OtaJobEventActivate callback from OTA Agent." ) );

            /* Activate the new firmware image. */
            OTA_ActivateNewImage();

            /* Shutdown OTA Agent, if it is required that the unsubscribe operations are not
             * performed while shutting down please set the second parameter to 0 instead of 1. */
            OTA_Shutdown( 0, 1 );

            /* Requires manual activation of new image.*/
            LogError( ( "New image activation failed." ) );

            break;

        case OtaJobEventFail:
            LogInfo( ( "Received OtaJobEventFail callback from OTA Agent." ) );

            /* Nothing special to do. The OTA agent handles it. */
            break;

        case OtaJobEventStartTest:

            /* This demo just accepts the image since it was a good OTA update and networking
             * and services are all working (or we would not have made it this far). If this
             * were some custom device that wants to test other things before validating new
             * image, this would be the place to kick off those tests before calling
             * OTA_SetImageState() with the final result of either accepted or rejected. */

            LogInfo( ( "Received OtaJobEventStartTest callback from OTA Agent." ) );
            err = OTA_SetImageState( OtaImageStateAccepted );

            if( err == OtaErrNone ) {
                /* Erasing passive partition */
                ret = otaPal_EraseLastBootPartition();
                if (ret != ESP_OK) {
                   ESP_LOGE("otaAppCallback", "Failed to erase last boot partition! (%d)", ret);
                }
            } else {
                LogError( ( " Failed to set image state as accepted." ) );
            }

            break;

        case OtaJobEventProcessed:
            LogDebug( ( "Received OtaJobEventProcessed callback from OTA Agent." ) );

            if( pData != NULL )
            {
                otaEventBufferFree( ( OtaEventData_t * ) pData );
            }

            break;

        case OtaJobEventSelfTestFailed:
            LogDebug( ( "Received OtaJobEventSelfTestFailed callback from OTA Agent." ) );

            /* Requires manual activation of previous image as self-test for
             * new image downloaded failed.*/
            LogError( ( "Self-test failed, shutting down OTA Agent." ) );

            /* Shutdown OTA Agent, if it is required that the unsubscribe operations are not
             * performed while shutting down please set the second parameter to 0 instead of 1. */
            OTA_Shutdown( 0, 1 );

            break;

        default:
            LogDebug( ( "Received invalid callback event from OTA Agent." ) );
    }
}


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

jobMessageType_t getJobMessageType( const char * pTopicName,
                                    uint16_t topicNameLength )
{
    uint16_t index = 0U;
    MQTTStatus_t mqttStatus = MQTTSuccess;
    bool isMatch = false;
    jobMessageType_t jobMessageIndex = jobMessageTypeMax;

    /* For suppressing compiler-warning: unused variable. */
    ( void ) mqttStatus;

    /* Lookup table for OTA job message string. */
    static const char * const pJobTopicFilters[ jobMessageTypeMax ] =
    {
        OTA_TOPIC_PREFIX OTA_TOPIC_JOBS "/$next/get/accepted",
        OTA_TOPIC_PREFIX OTA_TOPIC_JOBS "/notify-next",
    };

    /* Match the input topic filter against the wild-card pattern of topics filters
    * relevant for the OTA Update service to determine the type of topic filter. */
    for( ; index < jobMessageTypeMax; index++ )
    {
        mqttStatus = MQTT_MatchTopic( pTopicName,
                                      topicNameLength,
                                      pJobTopicFilters[ index ],
                                      strlen( pJobTopicFilters[ index ] ),
                                      &isMatch );
        assert( mqttStatus == MQTTSuccess );

        if( isMatch )
        {
            jobMessageIndex = index;
            break;
        }
    }

    return jobMessageIndex;
}

/*-----------------------------------------------------------*/

OtaEventData_t * otaEventBufferGet( void )
{
    uint32_t ulIndex = 0;
    OtaEventData_t * pFreeBuffer = NULL;

    if( osi_sem_take( &bufferSemaphore, 0 ) == 0 )
    {
        for( ulIndex = 0; ulIndex < otaconfigMAX_NUM_OTA_DATA_BUFFERS; ulIndex++ )
        {
            if( eventBuffer[ ulIndex ].bufferUsed == false )
            {
                eventBuffer[ ulIndex ].bufferUsed = true;
                pFreeBuffer = &eventBuffer[ ulIndex ];
                break;
            }
        }

        ( void ) osi_sem_give( &bufferSemaphore );
    }
    else
    {
        LogError( ( "Failed to get buffer semaphore: "
                    ",errno=%s",
                    strerror( errno ) ) );
    }

    return pFreeBuffer;
}

/*-----------------------------------------------------------*/

static void mqttJobCallback( MQTTContext_t * pContext,
                             MQTTPublishInfo_t * pPublishInfo )
{
    OtaEventData_t * pData;
    OtaEventMsg_t eventMsg = { 0 };
    jobMessageType_t jobMessageType = 0;

    assert( pPublishInfo != NULL );
    assert( pContext != NULL );

    ( void ) pContext;

    jobMessageType = getJobMessageType( pPublishInfo->pTopicName, pPublishInfo->topicNameLength );

    switch( jobMessageType )
    {
        case jobMessageTypeNextGetAccepted:
        case jobMessageTypeNextNotify:

            pData = otaEventBufferGet();

            if( pData != NULL )
            {
                memcpy( pData->data, pPublishInfo->pPayload, pPublishInfo->payloadLength );
                pData->dataLength = pPublishInfo->payloadLength;
                eventMsg.eventId = OtaAgentEventReceivedJobDocument;
                eventMsg.pEventData = pData;

                /* Send job document received event. */
                OTA_SignalEvent( &eventMsg );
            }
            else
            {
                LogError( ( "No OTA data buffers available." ) );
            }

            break;

        default:
// %zu
            LogInfo( ( "Received job message %s size %zu.\n\n",
                       pPublishInfo->pTopicName,
                       pPublishInfo->payloadLength ) );
    }
}

/*-----------------------------------------------------------*/

static void mqttDataCallback( MQTTContext_t * pContext,
                              MQTTPublishInfo_t * pPublishInfo )
{
    OtaEventData_t * pData;
    OtaEventMsg_t eventMsg = { 0 };

    assert( pPublishInfo != NULL );
    assert( pContext != NULL );

    ( void ) pContext;

    LogInfo( ( "Received data message callback, size %zu.\n\n", pPublishInfo->payloadLength ) );

    pData = otaEventBufferGet();

    if( pData != NULL )
    {
        memcpy( pData->data, pPublishInfo->pPayload, pPublishInfo->payloadLength );
        pData->dataLength = pPublishInfo->payloadLength;
        eventMsg.eventId = OtaAgentEventReceivedFileBlock;
        eventMsg.pEventData = pData;

        /* Send job document received event. */
        OTA_SignalEvent( &eventMsg );
    }
    else
    {
        LogError( ( "No OTA data buffers available." ) );
    }
}

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

static void registerSubscriptionManagerCallback( const char * pTopicFilter,
                                                 uint16_t topicFilterLength )
{
    bool isMatch = false;
    MQTTStatus_t mqttStatus = MQTTSuccess;
    SubscriptionManagerStatus_t subscriptionStatus = SUBSCRIPTION_MANAGER_SUCCESS;

    uint16_t index = 0U;

    /* For suppressing compiler-warning: unused variable. */
    ( void ) mqttStatus;

    /* Lookup table for OTA message string. */
    static const char * const pWildCardTopicFilters[] =
    {
        OTA_TOPIC_PREFIX OTA_TOPIC_JOBS "/#",
        OTA_TOPIC_PREFIX OTA_TOPIC_STREAM "/#"
    };

    /* Match the input topic filter against the wild-card pattern of topics filters
    * relevant for the OTA Update service to determine the type of topic filter. */
    for( ; index < 2; index++ )
    {
        mqttStatus = MQTT_MatchTopic( pTopicFilter,
                                      topicFilterLength,
                                      pWildCardTopicFilters[ index ],
                                      strlen( pWildCardTopicFilters[ index ] ),
                                      &isMatch );
        assert( mqttStatus == MQTTSuccess );

        if( isMatch )
        {
            /* Register callback to subscription manager. */
            subscriptionStatus = SubscriptionManager_RegisterCallback( pWildCardTopicFilters[ index ],
                                                                       strlen( pWildCardTopicFilters[ index ] ),
                                                                       otaMessageCallback[ index ] );

            if( subscriptionStatus != SUBSCRIPTION_MANAGER_SUCCESS )
            {
                LogWarn( ( "Failed to register a callback to subscription manager with error = %d.",
                           subscriptionStatus ) );
            }

            break;
        }
    }
}

/*-----------------------------------------------------------*/

static OtaMqttStatus_t mqttSubscribe( const char * pTopicFilter,
                                      uint16_t topicFilterLength,
                                      uint8_t qos )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;

    MQTTStatus_t mqttStatus = MQTTBadParameter;
    MQTTContext_t * pMqttContext = &mqttContext;
    MQTTSubscribeInfo_t pSubscriptionList[ 1 ];

    assert( pMqttContext != NULL );
    assert( pTopicFilter != NULL );
    assert( topicFilterLength > 0 );

    ( void ) qos;

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pSubscriptionList, 0x00, sizeof( pSubscriptionList ) );

    /* Set the topic and topic length. */
    pSubscriptionList[ 0 ].pTopicFilter = pTopicFilter;
    pSubscriptionList[ 0 ].topicFilterLength = topicFilterLength;

    if( pthread_mutex_lock( &mqttMutex ) == 0 )
    {
        /* Send SUBSCRIBE packet. */
        mqttStatus = MQTT_Subscribe( pMqttContext,
                                     pSubscriptionList,
                                     sizeof( pSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                                     MQTT_GetPacketId( pMqttContext ) );

        pthread_mutex_unlock( &mqttMutex );
    }
    else
    {
        LogError( ( "Failed to acquire mqtt mutex for executing MQTT_Subscribe"
                    ",errno=%s",
                    strerror( errno ) ) );
    }

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %u.",
                    mqttStatus ) );

        otaRet = OtaMqttSubscribeFailed;
    }
    else
    {
        LogInfo( ( "SUBSCRIBE topic %.*s to broker.\n\n",
                   topicFilterLength,
                   pTopicFilter ) );

        registerSubscriptionManagerCallback( pTopicFilter, topicFilterLength );
    }

    return otaRet;
}

/*-----------------------------------------------------------*/

static OtaMqttStatus_t mqttPublish( const char * const pacTopic,
                                    uint16_t topicLen,
                                    const char * pMsg,
                                    uint32_t msgSize,
                                    uint8_t qos )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;

    MQTTStatus_t mqttStatus = MQTTBadParameter;
    MQTTPublishInfo_t publishInfo = { 0 };
    MQTTContext_t * pMqttContext = &mqttContext;
    BackoffAlgorithmStatus_t backoffAlgStatus = BackoffAlgorithmSuccess;
    BackoffAlgorithmContext_t reconnectParams;
    uint16_t nextRetryBackOff;


    /* Initialize reconnect attempts and interval */
    BackoffAlgorithm_InitializeParams( &reconnectParams,
                                       CONNECTION_RETRY_BACKOFF_BASE_MS,
                                       CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS,
                                       MQTT_PUBLISH_RETRY_MAX_ATTEMPS );

    /* Set the required publish parameters. */
    publishInfo.pTopicName = pacTopic;
    publishInfo.topicNameLength = topicLen;
    publishInfo.qos = qos;
    publishInfo.pPayload = pMsg;
    publishInfo.payloadLength = msgSize;

    if( pthread_mutex_lock( &mqttMutex ) == 0 )
    {
        do
        {
            mqttStatus = MQTT_Publish( pMqttContext,
                                       &publishInfo,
                                       MQTT_GetPacketId( pMqttContext ) );

            if( qos == 1 )
            {
                /* Loop to receive packet from transport interface. */
                mqttStatus = MQTT_ReceiveLoop( &mqttContext );
            }

            if( mqttStatus != MQTTSuccess )
            {
                /* Generate a random number and get back-off value (in milliseconds) for the next connection retry. */
                backoffAlgStatus = BackoffAlgorithm_GetNextBackoff( &reconnectParams, generateRandomNumber(), &nextRetryBackOff );

                if( backoffAlgStatus == BackoffAlgorithmRetriesExhausted )
                {
                    LogError( ( "Publish failed, all attempts exhausted." ) );
                }
                else if( backoffAlgStatus == BackoffAlgorithmSuccess )
                {
                    LogWarn( ( "Publish failed. Retrying connection "
                               "after %hu ms backoff.",
                               ( unsigned short ) nextRetryBackOff ) );
                    vTaskDelay( nextRetryBackOff/portTICK_PERIOD_MS );
                }
            }
        } while( ( mqttStatus != MQTTSuccess ) && ( backoffAlgStatus == BackoffAlgorithmSuccess ) );

        pthread_mutex_unlock( &mqttMutex );
    }
    else
    {
        LogError( ( "Failed to acquire mqtt mutex for executing MQTT_Publish"
                    ",errno=%s",
                    strerror( errno ) ) );
    }

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send PUBLISH packet to broker with error = %u.", mqttStatus ) );

        otaRet = OtaMqttPublishFailed;
    }
    else
    {
        LogInfo( ( "Sent PUBLISH packet to broker %.*s to broker.\n\n",
                   topicLen,
                   pacTopic ) );
    }

    return otaRet;
}

/*-----------------------------------------------------------*/

static OtaMqttStatus_t mqttUnsubscribe( const char * pTopicFilter,
                                        uint16_t topicFilterLength,
                                        uint8_t qos )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;
    MQTTStatus_t mqttStatus = MQTTBadParameter;

    MQTTSubscribeInfo_t pSubscriptionList[ 1 ];
    MQTTContext_t * pMqttContext = &mqttContext;

    ( void ) qos;

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pSubscriptionList, 0x00, sizeof( pSubscriptionList ) );

    /* Set the topic and topic length. */
    pSubscriptionList[ 0 ].pTopicFilter = pTopicFilter;
    pSubscriptionList[ 0 ].topicFilterLength = topicFilterLength;

    if( pthread_mutex_lock( &mqttMutex ) == 0 )
    {
        /* Send UNSUBSCRIBE packet. */
        mqttStatus = MQTT_Unsubscribe( pMqttContext,
                                       pSubscriptionList,
                                       sizeof( pSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                                       MQTT_GetPacketId( pMqttContext ) );

        pthread_mutex_unlock( &mqttMutex );
    }
    else
    {
        LogError( ( "Failed to acquire mutex for executing MQTT_Unsubscribe"
                    ",errno=%s",
                    strerror( errno ) ) );
    }

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send UNSUBSCRIBE packet to broker with error = %u.",
                    mqttStatus ) );

        otaRet = OtaMqttUnsubscribeFailed;
    }
    else
    {
        LogInfo( ( "UNSUBSCRIBE topic %.*s to broker.\n\n",
                   topicFilterLength,
                   pTopicFilter ) );
    }

    return otaRet;
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
            status = EstablishMqttSession( provisioningPublishCallback,
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

static void setOtaInterfaces( OtaInterfaces_t * pOtaInterfaces )
{
    /* Initialize OTA library OS Interface. */
    pOtaInterfaces->os.event.init = OtaInitEvent_FreeRTOS;
    pOtaInterfaces->os.event.send = OtaSendEvent_FreeRTOS;
    pOtaInterfaces->os.event.recv = OtaReceiveEvent_FreeRTOS;
    pOtaInterfaces->os.event.deinit = OtaDeinitEvent_FreeRTOS;
    pOtaInterfaces->os.timer.start = OtaStartTimer_FreeRTOS;
    pOtaInterfaces->os.timer.stop = OtaStopTimer_FreeRTOS;
    pOtaInterfaces->os.timer.delete = OtaDeleteTimer_FreeRTOS;
    pOtaInterfaces->os.mem.malloc = Malloc_FreeRTOS;
    pOtaInterfaces->os.mem.free = Free_FreeRTOS;

    /* Initialize the OTA library MQTT Interface.*/
    pOtaInterfaces->mqtt.subscribe = mqttSubscribe;
    pOtaInterfaces->mqtt.publish = mqttPublish;
    pOtaInterfaces->mqtt.unsubscribe = mqttUnsubscribe;

    /* Initialize the OTA library PAL Interface.*/
    pOtaInterfaces->pal.getPlatformImageState = otaPal_GetPlatformImageState;
    pOtaInterfaces->pal.setPlatformImageState = otaPal_SetPlatformImageState;
    pOtaInterfaces->pal.writeBlock = otaPal_WriteBlock;
    pOtaInterfaces->pal.activate = otaPal_ActivateNewImage;
    pOtaInterfaces->pal.closeFile = otaPal_CloseFile;
    pOtaInterfaces->pal.reset = otaPal_ResetDevice;
    pOtaInterfaces->pal.abort = otaPal_Abort;
    pOtaInterfaces->pal.createFile = otaPal_CreateFileForRx;
}

/*-----------------------------------------------------------*/

static void * otaThread( void * pParam )
{
    /* Calling OTA agent task. */
    LogInfo( ( "Calling OTA agent task." ) );
    OTA_EventProcessingTask( pParam );
    LogInfo( ( "OTA Agent stopped." ) );
    return NULL;
}
/*-----------------------------------------------------------*/

#define CLIENT_IDENTIFIER_PREFIX "ESP32Thing_"
#define MAX_CLIENT_IDENTIFIER_LENGTH  (sizeof(CLIENT_IDENTIFIER_PREFIX) + sizeof(CLIENT_IDENTIFIER) - 1)

int startOTADemo( void )
{
    /* Status indicating a successful demo or not. */
    int returnStatus = EXIT_SUCCESS;

    /* coreMQTT library return status. */
    MQTTStatus_t mqttStatus = MQTTBadParameter;

    /* OTA library return status. */
    OtaErr_t otaRet = OtaErrNone;

    /* OTA Agent state returned from calling OTA_GetAgentState.*/
    OtaState_t state = OtaAgentStateStopped;

    /* OTA event message used for sending event to OTA Agent.*/
    OtaEventMsg_t eventMsg = { 0 };

    /* OTA library packet statistics per job.*/
    OtaAgentStatistics_t otaStatistics = { 0 };

    /* OTA Agent thread handle.*/
    pthread_t threadHandle;

    /* Status return from call to pthread_join. */
    int returnJoin = 0;

    /* OTA interface context required for library interface functions.*/
    OtaInterfaces_t otaInterfaces;

    /* Maximum time to wait for the OTA agent to get suspended. */
    int16_t suspendTimeout;

    /* Initialize semaphore for buffer operations. */
    if( osi_sem_new( &bufferSemaphore, 0x7FFFU, 1 ) != 0 )
    {
        LogError( ( "Failed to initialize buffer semaphore"
                    ",errno=%s",
                    strerror( errno ) ) );

        returnStatus = EXIT_FAILURE;
    }

    /* Initialize semaphore for ack. */
    if( osi_sem_new( &ackSemaphore, 0x7FFFU, 0 ) != 0 )
    {
        LogError( ( "Failed to initialize ack semaphore"
                    ",errno=%s",
                    strerror( errno ) ) );

        returnStatus = EXIT_FAILURE;
    }

    /* Initialize mutex for coreMQTT APIs. */
    if( pthread_mutex_init( &mqttMutex, NULL ) != 0 )
    {
        LogError( ( "Failed to initialize mutex for mqtt apis"
                    ",errno=%s",
                    strerror( errno ) ) );

        returnStatus = EXIT_FAILURE;
    }

    /* Set OTA Library interfaces.*/
    setOtaInterfaces( &otaInterfaces );

    /* Set OTA Code Signing Certificate */
    if( !otaPal_SetCodeSigningCertificate( pcAwsCodeSigningCertPem ) )
    {
         LogError( ( "Failed to allocate memory for Code Signing Certificate" ) );
         returnStatus = EXIT_FAILURE;
    }

    LogInfo( ( "OTA over MQTT demo, Application version %u.%u.%u",
               appFirmwareVersion.u.x.major,
               appFirmwareVersion.u.x.minor,
               appFirmwareVersion.u.x.build ) );

    /****************************** Init OTA Library. ******************************/

    if( returnStatus == EXIT_SUCCESS )
    {
        char fullClientIdentifier[MAX_CLIENT_IDENTIFIER_LENGTH];
        snprintf(fullClientIdentifier, sizeof(fullClientIdentifier), "%s%s", CLIENT_IDENTIFIER_PREFIX, CLIENT_IDENTIFIER);

        if( ( otaRet = OTA_Init( &otaBuffer,
                                 &otaInterfaces,
                                 (const uint8_t *)(fullClientIdentifier),
                                 otaAppCallback ) ) != OtaErrNone )
        {
            LogError( ( "Failed to initialize OTA Agent, exiting = %u.",
                        otaRet ) );

            returnStatus = EXIT_FAILURE;
        }
    }

    /****************************** Create OTA Task. ******************************/

    if( returnStatus == EXIT_SUCCESS )
    {
        LogInfo( ( "Initialized OTA Agent, now trying OTA thread." ) );
        ESP_LOGI("TAG", "Free memory: %"PRIu32" bytes", esp_get_free_heap_size());

        int pthread_status = pthread_create( &threadHandle, NULL, otaThread, NULL );
        if( pthread_status != 0 )
        {            
            LogError( ( "Failed to create OTA thread: "
                        ",errno=%s",
                        strerror( errno ) ) );
            LogError( ( "Pthread status number: %d",
                        pthread_status ) );

            returnStatus = EXIT_FAILURE;
        }
    }

    /****************************** OTA Demo loop. ******************************/

    if( returnStatus == EXIT_SUCCESS )
    {
        /* Wait till OTA library is stopped, output statistics for currently running
         * OTA job */
        while( ( ( state = OTA_GetState() ) != OtaAgentStateStopped ) )
        {
            /* Check if OTA process was suspended and resume if required. */
            if( state == OtaAgentStateSuspended )
            {
                /* Resume OTA operations. */
                OTA_Resume();
            }
            else
            {
            /* Send start event to OTA Agent.*/
                eventMsg.eventId = OtaAgentEventStart;
                OTA_SignalEvent( &eventMsg );
            }

            /* Acquire the mqtt mutex lock. */
            if( pthread_mutex_lock( &mqttMutex ) == 0 )
            {
                /* Loop to receive packet from transport interface. */
                mqttStatus = MQTT_ProcessLoop( &mqttContext );

                pthread_mutex_unlock( &mqttMutex );
            }
            else
            {
                LogError( ( "Failed to acquire mutex to execute process loop"
                            ",errno=%s",
                            strerror( errno ) ) );
            }

            if( ( mqttStatus == MQTTSuccess ) || ( mqttStatus == MQTTNeedMoreBytes ) )
            {
                /* Get OTA statistics for currently executing job. */
                OTA_GetStatistics( &otaStatistics );

                LogInfo( ( " Received: %"PRIu32"   Queued: %"PRIu32"   Processed: %"PRIu32"   Dropped: %"PRIu32"",
                            otaStatistics.otaPacketsReceived,
                            otaStatistics.otaPacketsQueued,
                            otaStatistics.otaPacketsProcessed,
                            otaStatistics.otaPacketsDropped ) );

                /* Delay to allow data to buffer for MQTT_ProcessLoop. */
                Clock_SleepMs( OTA_EXAMPLE_LOOP_SLEEP_PERIOD_MS );
            }
            else
            {
                LogInfo(("ovdje sam rođak"));
                LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                            MQTT_Status_strerror( mqttStatus ) ) );

                /* Disconnect from broker and close connection. */
                DisconnectMqttSession();

                /* Suspend OTA operations. */
                otaRet = OTA_Suspend();

                if( otaRet == OtaErrNone )
                {
                    suspendTimeout = OTA_SUSPEND_TIMEOUT_MS;

                    while( ( ( state = OTA_GetState() ) != OtaAgentStateSuspended ) && ( suspendTimeout > 0 ) )
                    {
                        /* Wait for OTA Library state to suspend */
                        Clock_SleepMs( OTA_EXAMPLE_TASK_DELAY_MS );
                        suspendTimeout -= OTA_EXAMPLE_TASK_DELAY_MS;
                    }
                }
                else
                {
                    LogError( ( "OTA failed to suspend. "
                                "StatusCode=%d.", otaRet ) );
                }
            }
        }
    }

    /****************************** Wait for OTA Thread. ******************************/

    if( returnStatus == EXIT_SUCCESS )
    {
        returnJoin = pthread_join( threadHandle, NULL );

        if( returnJoin != 0 )
        {
            LogError( ( "Failed to join thread"
                        ",error code = %d",
                        returnJoin ) );

            returnStatus = EXIT_FAILURE;
        }
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/
