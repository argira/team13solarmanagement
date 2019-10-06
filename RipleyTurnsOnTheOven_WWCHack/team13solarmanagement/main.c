/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

// This sample C application for Azure Sphere demonstrates Azure IoT SDK C APIs
// The application uses the Azure IoT SDK C APIs to
// 1. Use the buttons to trigger sending telemetry to Azure IoT Hub/Central.
// 2. Use IoT Hub/Device Twin to control an LED.

// You will need to provide four pieces of information to use this application, all of which are set
// in the app_manifest.json.
// 1. The IoT Hub Endpoint address for your IoT Central application (set in 'AllowedConnections')

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

// applibs_versions.h defines the API struct versions to use for applibs APIs.
#include "applibs_versions.h"
#include <applibs/log.h>
#include <applibs/networking.h>
#include <applibs/gpio.h>
#include <applibs/storage.h>
#include <applibs/uart.h>
#include <applibs/uart.h>

// By default, this sample is targeted at the MT3620 Reference Development Board (RDB).
// This can be changed using the project property "Target Hardware Definition Directory".
// This #include imports the sample_hardware abstraction from that hardware definition.
#include <hw/mt3620_rdb.h>

#include "epoll_timerfd_utilities.h"

// Azure IoT SDK
#include <iothub_client_core_common.h>
#include <iothub_device_client_ll.h>
#include <iothub_client_options.h>
#include <iothubtransportmqtt.h>
#include <iothub.h>
#include <azure_sphere_provisioning.h>
#include "parson.h" // used to parse Device Twin messages.

//
// String containing Hostname, Device Id & Device Key in the format:
// "HostName=<host_name>;DeviceId=<device_id>;SharedAccessKey=<device_key>"
//
// Note: this connection string is specific to the device "clockcurl". To configure other devices,
// see information on iothub-explorer at http://aka.ms/iothubgetstartedVSCS
//
static const char connectionString[] = "HostName=solarenergy.azure-devices.net;DeviceId=team13wwc;SharedAccessKey=4GgaGfQyRw6AZmucf9tuv5wZSdU9f6sCgAzpv70V4Pk=";

// File descriptors - initialized to invalid value
static int uartFd = -1;

const char AzureIoTCertificatesX[] =
/* Baltimore */
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\r\n"
"RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\r\n"
"VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX\r\n"
"DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y\r\n"
"ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy\r\n"
"VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr\r\n"
"mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr\r\n"
"IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK\r\n"
"mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu\r\n"
"XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy\r\n"
"dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye\r\n"
"jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1\r\n"
"BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3\r\n"
"DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92\r\n"
"9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx\r\n"
"jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0\r\n"
"Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz\r\n"
"ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS\r\n"
"R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp\r\n"
"-----END CERTIFICATE-----\r\n"
/* MSIT */
"-----BEGIN CERTIFICATE-----\r\n"
"MIIFhjCCBG6gAwIBAgIEByeaqTANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJJ\r\n"
"RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\r\n"
"VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTEzMTIxOTIwMDczMloX\r\n"
"DTE3MTIxOTIwMDY1NVowgYsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n\r\n"
"dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y\r\n"
"YXRpb24xFTATBgNVBAsTDE1pY3Jvc29mdCBJVDEeMBwGA1UEAxMVTWljcm9zb2Z0\r\n"
"IElUIFNTTCBTSEEyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0eg3\r\n"
"p3aKcEsZ8CA3CSQ3f+r7eOYFumqtTicN/HJq2WwhxGQRlXMQClwle4hslAT9x9uu\r\n"
"e9xKCLM+FvHQrdswbdcaHlK1PfBHGQPifaa9VxM/VOo6o7F3/ELwY0lqkYAuMEnA\r\n"
"iusrr/466wddBvfp/YQOkb0JICnobl0JzhXT5+/bUOtE7xhXqwQdvDH593sqE8/R\r\n"
"PVGvG8W1e+ew/FO7mudj3kEztkckaV24Rqf/ravfT3p4JSchJjTKAm43UfDtWBpg\r\n"
"lPbEk9jdMCQl1xzrGZQ1XZOyrqopg3PEdFkFUmed2mdROQU6NuryHnYrFK7sPfkU\r\n"
"mYsHbrznDFberL6u23UykJ5jvXS/4ArK+DSWZ4TN0UI4eMeZtgzOtg/pG8v0Wb4R\r\n"
"DsssMsj6gylkeTyLS/AydGzzk7iWa11XWmjBzAx5ihne9UkCXgiAAYkMMs3S1pbV\r\n"
"S6Dz7L+r9H2zobl82k7X5besufIlXwHLjJaoKK7BM1r2PwiQ3Ov/OdgmyBKdHJqq\r\n"
"qcAWjobtZ1KWAH8Nkj092XA25epCbx+uleVbXfjQOsfU3neG0PyeTuLiuKloNwnE\r\n"
"OeOFuInzH263bR9KLxgJb95KAY8Uybem7qdjnzOkVHxCg2i4pd+/7LkaXRM72a1o\r\n"
"/SAKVZEhZPnXEwGgCF1ZiRtEr6SsxwUQ+kFKqPsCAwEAAaOCASAwggEcMBIGA1Ud\r\n"
"EwEB/wQIMAYBAf8CAQAwUwYDVR0gBEwwSjBIBgkrBgEEAbE+AQAwOzA5BggrBgEF\r\n"
"BQcCARYtaHR0cDovL2N5YmVydHJ1c3Qub21uaXJvb3QuY29tL3JlcG9zaXRvcnku\r\n"
"Y2ZtMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH\r\n"
"AwIwHwYDVR0jBBgwFoAU5Z1ZMIJHWMys+ghUNoZ7OrUETfAwQgYDVR0fBDswOTA3\r\n"
"oDWgM4YxaHR0cDovL2NkcDEucHVibGljLXRydXN0LmNvbS9DUkwvT21uaXJvb3Qy\r\n"
"MDI1LmNybDAdBgNVHQ4EFgQUUa8kJpz0aCJXgCYrO0ZiFXsezKUwDQYJKoZIhvcN\r\n"
"AQELBQADggEBAHaFxSMxH7Rz6qC8pe3fRUNqf2kgG4Cy+xzdqn+I0zFBNvf7+2ut\r\n"
"mIx4H50RZzrNS+yovJ0VGcQ7C6eTzuj8nVvoH8tWrnZDK8cTUXdBqGZMX6fR16p1\r\n"
"xRspTMn0baFeoYWTFsLLO6sUfUT92iUphir+YyDK0gvCNBW7r1t/iuCq7UWm6nnb\r\n"
"2DVmVEPeNzPR5ODNV8pxsH3pFndk6FmXudUu0bSR2ndx80oPSNI0mWCVN6wfAc0Q\r\n"
"negqpSDHUJuzbEl4K1iSZIm4lTaoNKrwQdKVWiRUl01uBcSVrcR6ozn7eQaKm6ZP\r\n"
"2SL6RE4288kPpjnngLJev7050UblVUfbvG4=\r\n"
"-----END CERTIFICATE-----\r\n"
/* *.azure-devices.net */
"-----BEGIN CERTIFICATE-----\r\n"
"MIIGcjCCBFqgAwIBAgITWgABtrNbz7vBeV0QWwABAAG2szANBgkqhkiG9w0BAQsF\r\n"
"ADCBizELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT\r\n"
"B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEVMBMGA1UE\r\n"
"CxMMTWljcm9zb2Z0IElUMR4wHAYDVQQDExVNaWNyb3NvZnQgSVQgU1NMIFNIQTIw\r\n"
"HhcNMTUwODI3MDMxODA0WhcNMTcwODI2MDMxODA0WjAeMRwwGgYDVQQDDBMqLmF6\r\n"
"dXJlLWRldmljZXMubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\r\n"
"nXC/qBUdlnfIm5K3HYu0o/Mb5tNNcsr0xy4Do0Puwq2W1tz0ZHvIIS9VOANhkNCb\r\n"
"VyOncnP6dvmM/rYYKth/NQ8RUiZOYlROZ0SYC8cvxq9WOln4GXtEU8vNVqJbYrJj\r\n"
"rPMHfxqLzTE/0ZnQffnDT3iMUE9kFLHow0YgaSRU0KZsc9KAROmzBzu+QIB1WGKX\r\n"
"D7CN361tG1UuN68Bz7MSnbgk98Z+DjDxfusoDhiiy/Y9MLOJMt4WIy5BqL3lfLnn\r\n"
"r+JLqmpiFuyVUDacFQDprYJ1/AFgcsKYu/ydmASARPzqJhOGaC2sZP0U5oBOoBzI\r\n"
"bz4tfn8Bi0kJKmS53mQt+wIDAQABo4ICOTCCAjUwCwYDVR0PBAQDAgSwMB0GA1Ud\r\n"
"JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUKpYehBSNA53Oxivn\r\n"
"aLCz3+eFUJ0wXQYDVR0RBFYwVIITKi5henVyZS1kZXZpY2VzLm5ldIIaKi5hbXFw\r\n"
"d3MuYXp1cmUtZGV2aWNlcy5uZXSCISouc3UubWFuYWdlbWVudC1henVyZS1kZXZp\r\n"
"Y2VzLm5ldDAfBgNVHSMEGDAWgBRRryQmnPRoIleAJis7RmIVex7MpTB9BgNVHR8E\r\n"
"djB0MHKgcKBuhjZodHRwOi8vbXNjcmwubWljcm9zb2Z0LmNvbS9wa2kvbXNjb3Jw\r\n"
"L2NybC9tc2l0d3d3Mi5jcmyGNGh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv\r\n"
"bXNjb3JwL2NybC9tc2l0d3d3Mi5jcmwwcAYIKwYBBQUHAQEEZDBiMDwGCCsGAQUF\r\n"
"BzAChjBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL21zY29ycC9tc2l0d3d3\r\n"
"Mi5jcnQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLm1zb2NzcC5jb20wTgYDVR0g\r\n"
"BEcwRTBDBgkrBgEEAYI3KgEwNjA0BggrBgEFBQcCARYoaHR0cDovL3d3dy5taWNy\r\n"
"b3NvZnQuY29tL3BraS9tc2NvcnAvY3BzADAnBgkrBgEEAYI3FQoEGjAYMAoGCCsG\r\n"
"AQUFBwMBMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4ICAQCrjzOSW+X6v+UC\r\n"
"u+JkYyuypXN14pPLcGFbknJWj6DAyFWXKC8ihIYdtf/szWIO7VooplSTZ05u/JYu\r\n"
"ZYh7fAw27qih9CLhhfncXi5yzjgLMlD0mlbORvMJR/nMl7Yh1ki9GyLnpOqMmO+E\r\n"
"yTpOiE07Uyt2uWelLHjMY8kwy2bSRXIp7/+A8qHRaIIdXNtAKIK5jo068BJpo77h\r\n"
"4PljCb9JFdEt6sAKKuaP86Y+8oRZ7YzU4TLDCiK8P8n/gQXH0vvhOE/O0n7gWPqB\r\n"
"n8KxsnRicop6tB6GZy32Stn8w0qktmQNXOGU+hp8OL6irULWZw/781po6d78nmwk\r\n"
"1IFl2TB4+jgyblvJdTM0rx8vPf3F2O2kgsRNs9M5qCI7m+he43Bhue0Fj/h3oIIo\r\n"
"Qx7X/uqc8j3VTNE9hf2A4wksSRgRydjAYoo+bduNagC5s7Eucb4mBG0MMk7HAQU9\r\n"
"m/gyaxqth6ygDLK58wojSV0i4RiU01qZkHzqIWv5FhhMjbFwyKEc6U35Ps7kP/1O\r\n"
"fdGm13ONaYqDl44RyFsLFFiiDYxZFDSsKM0WDxbl9ULAlVc3WR85kEBK6I+pSQj+\r\n"
"7/Z5z2zTz9qOFWgB15SegTbjSR7uk9mEVnj9KDlGtG8W1or0EGrrEDP2CMsp0oEj\r\n"
"VTJbZAxEaZ3cVCKva5sQUxFMjwG32g==\r\n"
"-----END CERTIFICATE-----\r\n";

static volatile sig_atomic_t terminationRequired = false;

// Maximum amount of time to attempt reconnection when the connection to the IoT Hub drops.
// Time expressed in seconds. A value of 0 means to retry forever.</remarks>
static const size_t retryTimeoutSeconds = 0;

// Azure IoT Hub defines
static IOTHUB_DEVICE_CLIENT_LL_HANDLE iothubClientHandle = NULL;
static const int keepalivePeriodSeconds = 20;
static bool iothubConnected = false;
static void SendMessageCallback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* context);
static void TwinCallback(DEVICE_TWIN_UPDATE_STATE updateState, const unsigned char* payload,
    size_t payloadSize, void* userContextCallback);
static void TwinReportBoolState(const char* propertyName, bool propertyValue);
static void ReportStatusCallback(int result, void* context);
static const char* GetReasonString(IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason);
static void SendTelemetry(const unsigned char* key, const unsigned char* value);
static void SetupAzureClient(void);

// Function to generate simulated Temperature data/telemetry
static void SendSimulatedTemperature(void);

// Initialization/Cleanup
static int InitPeripheralsAndHandlers(void);
static void ClosePeripheralsAndHandlers(void);

// File descriptors - initialized to invalid value
// Buttons
static int sendMessageButtonGpioFd = -1;
static int sendOrientationButtonGpioFd = -1;

// LED
static int deviceTwinStatusLedGpioFd = -1;
static int deviceTwinRipleyLedGpioFd = -1;
static bool statusLedOn = false;
static bool ovenLedOn = false;

// Timer / polling
static int buttonPollTimerFd = -1;
static int azureTimerFd = -1;
static int epollFd = -1;

// Azure IoT poll periods
static const int AzureIoTDefaultPollPeriodSeconds = 5;

static int azureIoTPollPeriodSeconds = -1;

// Button state variables
static GPIO_Value_Type sendMessageButtonState = GPIO_Value_High;
static GPIO_Value_Type sendOrientationButtonState = GPIO_Value_High;

static void ButtonPollTimerEventHandler(EventData* eventData);
static bool IsButtonPressed(int fd, GPIO_Value_Type* oldState);
static void SendMessageButtonHandler(void);
static void SendOrientationButtonHandler(void);
static bool deviceIsUp = false; // Orientation
static void AzureTimerEventHandler(EventData* eventData);

/// <summary>
///     Signal handler for termination requests. This handler must be async-signal-safe.
/// </summary>
static void TerminationHandler(int signalNumber)
{
    // Don't use Log_Debug here, as it is not guaranteed to be async-signal-safe.
    terminationRequired = true;
}
/// <summary>
///     Handle UART event: if there is incoming data, print it.
/// </summary>
static void UartEventHandler(EventData *eventData)
{
	const size_t receiveBufferSize = 256;
	uint8_t receiveBuffer[receiveBufferSize + 1]; // allow extra byte for string termination
	ssize_t bytesRead;

	// Read incoming UART data. It is expected behavior that messages may be received in multiple
	// partial chunks.
	bytesRead = read(uartFd, receiveBuffer, receiveBufferSize);
	if (bytesRead < 0) {
		Log_Debug("ERROR: Could not read UART: %s (%d).\n", strerror(errno), errno);
		terminationRequired = true;
		return;
	}

	if (bytesRead > 0) {
		// Null terminate the buffer to make it a valid string, and print it
		receiveBuffer[bytesRead] = 0;
		Log_Debug("UART received %d bytes: '%s'.\n", bytesRead, (char *)receiveBuffer);
	}
}

static EventData uartEventData = { .eventHandler = &UartEventHandler };

/// <summary>
///     Set up SIGTERM termination handler, initialize peripherals, and set up event handlers.
/// </summary>
/// <returns>0 on success, or -1 on failure</returns>

/// <summary>
///     Close peripherals and handlers.
/// </summary>




/// <summary>
///     Main entry point for this sample.
/// </summary>
int main(int argc, char* argv[])
{
    Log_Debug("IoT Hub - connection string starting.\n");

    if (InitPeripheralsAndHandlers() != 0) {
        terminationRequired = true;
    }

    // Main loop
    while (!terminationRequired) {
        if (WaitForEventAndCallHandler(epollFd) != 0) {
            terminationRequired = true;
        }
    }

    ClosePeripheralsAndHandlers();

    Log_Debug("Application exiting.\n");

    return 0;
}

/// <summary>
/// Button timer event:  Check the status of buttons A and B
/// </summary>
static void ButtonPollTimerEventHandler(EventData* eventData)
{
    if (ConsumeTimerFdEvent(buttonPollTimerFd) != 0) {
        terminationRequired = true;
        return;
    }
    SendMessageButtonHandler();
    SendOrientationButtonHandler();
}

/// <summary>
/// Azure timer event:  Check connection status and send telemetry
/// </summary>
static void AzureTimerEventHandler(EventData* eventData)
{
    if (ConsumeTimerFdEvent(azureTimerFd) != 0) {
        terminationRequired = true;
        return;
    }

    bool isNetworkReady = false;
    if (Networking_IsNetworkingReady(&isNetworkReady) != -1) {
        if (isNetworkReady && !iothubConnected) {
            SetupAzureClient();
        }
    }
    else {
        Log_Debug("Failed to get Network state\n");
    }

    if (iothubConnected) {
        SendSimulatedTemperature();
        IoTHubDeviceClient_LL_DoWork(iothubClientHandle);
    }
}

// event handler data structures. Only the event handler field needs to be populated.
static EventData buttonPollEventData = { .eventHandler = &ButtonPollTimerEventHandler };
static EventData azureEventData = { .eventHandler = &AzureTimerEventHandler };

/// <summary>
///     Set up SIGTERM termination handler, initialize peripherals, and set up event handlers.
/// </summary>
/// <returns>0 on success, or -1 on failure</returns>
static int InitPeripheralsAndHandlers(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = TerminationHandler;
    sigaction(SIGTERM, &action, NULL);

    epollFd = CreateEpollFd();
    if (epollFd < 0) {
        return -1;
    }

    // Open button A GPIO as input
    Log_Debug("Opening SAMPLE_BUTTON_1 as input\n");
    sendMessageButtonGpioFd = GPIO_OpenAsInput(MT3620_RDB_BUTTON_A);
    if (sendMessageButtonGpioFd < 0) {
        Log_Debug("ERROR: Could not open button A: %s (%d).\n", strerror(errno), errno);
        return -1;
    }

    // Open button B GPIO as input
    Log_Debug("Opening SAMPLE_BUTTON_2 as input\n");
    sendOrientationButtonGpioFd = GPIO_OpenAsInput(MT3620_RDB_BUTTON_B);
    if (sendOrientationButtonGpioFd < 0) {
        Log_Debug("ERROR: Could not open button B: %s (%d).\n", strerror(errno), errno);
        return -1;
    }

    // LED 4 Blue is used to show Device Twin settings state
    Log_Debug("Opening MT3620_RDB_LED4_BLUE as output\n");
    deviceTwinStatusLedGpioFd =
        GPIO_OpenAsOutput(MT3620_RDB_LED4_BLUE, GPIO_OutputMode_PushPull, GPIO_Value_High);
    if (deviceTwinStatusLedGpioFd < 0) {
        Log_Debug("ERROR: Could not open LED: %s (%d).\n", strerror(errno), errno);
        return -1;
    }

    // LED 1 Green is used to show Device Twin settings state
    Log_Debug("Opening MT3620_RDB_LED1_GREEN as output\n");
    deviceTwinRipleyLedGpioFd =
        GPIO_OpenAsOutput(MT3620_RDB_LED1_GREEN, GPIO_OutputMode_PushPull, GPIO_Value_High);
    if (deviceTwinRipleyLedGpioFd < 0) {
        Log_Debug("ERROR: Could not open LED: %s (%d).\n", strerror(errno), errno);
        return -1;
    }

    // Set up a timer to poll for button events.
    struct timespec buttonPressCheckPeriod = { 0, 1000 * 1000 };
    buttonPollTimerFd =
        CreateTimerFdAndAddToEpoll(epollFd, &buttonPressCheckPeriod, &buttonPollEventData, EPOLLIN);
    if (buttonPollTimerFd < 0) {
        return -1;
    }

    azureIoTPollPeriodSeconds = AzureIoTDefaultPollPeriodSeconds;
    struct timespec azureTelemetryPeriod = { azureIoTPollPeriodSeconds, 0 };
    azureTimerFd =
        CreateTimerFdAndAddToEpoll(epollFd, &azureTelemetryPeriod, &azureEventData, EPOLLIN);
    if (azureTimerFd < 0) {
        return -1;
    }
	// Create a UART_Config object, open the UART and set up UART event handler
	UART_Config uartConfig;
	UART_InitConfig(&uartConfig);
	uartConfig.baudRate = 9600;
	uartConfig.flowControl = UART_FlowControl_None;
	uartFd = UART_Open(MT3620_RDB_HEADER2_ISU0_UART, &uartConfig);
	if (uartFd < 0) {
		Log_Debug("ERROR: Could not open UART: %s (%d).\n", strerror(errno), errno);
		return -1;
	}
	if (RegisterEventHandlerToEpoll(epollFd, uartFd, &uartEventData, EPOLLIN) != 0) {
		return -1;
	}
    return 0;
}

/// <summary>
///     Close peripherals and handlers.
/// </summary>
static void ClosePeripheralsAndHandlers(void)
{
    Log_Debug("Closing file descriptors\n");

    // Leave the LEDs off
    if (deviceTwinStatusLedGpioFd >= 0) {
        GPIO_SetValue(deviceTwinStatusLedGpioFd, GPIO_Value_High);
    }
    if (deviceTwinRipleyLedGpioFd >= 0) {
        GPIO_SetValue(deviceTwinRipleyLedGpioFd, GPIO_Value_High);
    }

    CloseFdAndPrintError(buttonPollTimerFd, "ButtonTimer");
    CloseFdAndPrintError(azureTimerFd, "AzureTimer");
    CloseFdAndPrintError(sendMessageButtonGpioFd, "SendMessageButton");
    CloseFdAndPrintError(sendOrientationButtonGpioFd, "SendOrientationButton");
    CloseFdAndPrintError(deviceTwinStatusLedGpioFd, "StatusLed");
    CloseFdAndPrintError(deviceTwinRipleyLedGpioFd, "deviceTwinRipleyLedGpioFd");
    CloseFdAndPrintError(epollFd, "Epoll");


	Log_Debug("Closing file descriptors.\n");
	CloseFdAndPrintError(uartFd, "Uart");
	///CloseFdAndPrintError(epollFd, "Epoll");
}

/// <summary>
///     Sets the IoT Hub authentication state for the app
///     The SAS Token expires which will set the authentication state
/// </summary>
static void HubConnectionStatusCallback(IOTHUB_CLIENT_CONNECTION_STATUS result,
    IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason,
    void* userContextCallback)
{
    iothubConnected = (result == IOTHUB_CLIENT_CONNECTION_AUTHENTICATED);
    if (iothubConnected)
        Log_Debug("INFO - HubConnectionStatusCallback: connection to the IoT Hub has been established.\n");
    if (!iothubConnected) {
        //Log_Debug("INFO: IoT Hub connection is down, retrying connection in 5 seconds...\n");
        Log_Debug("IoT Hub Connection Failed: %s\n", GetReasonString(reason));
    }
}

/// <summary>
///     Sets up the Azure IoT Hub connection (creates the iothubClientHandle)
/// </summary>
static void SetupAzureClient(void)
{
    if (iothubClientHandle != NULL) {
        IoTHubDeviceClient_LL_Destroy(iothubClientHandle);
    }

    iothubClientHandle =
        IoTHubDeviceClient_LL_CreateFromConnectionString(connectionString, MQTT_Protocol);

    if (iothubClientHandle == NULL) {
        Log_Debug("couldn't create the client from connection string");
        return;
    }

    IOTHUB_CLIENT_RESULT azureRes =
        IoTHubDeviceClient_LL_SetOption(iothubClientHandle, "TrustedCerts", AzureIoTCertificatesX);
    if (azureRes != IOTHUB_CLIENT_OK) {
        Log_Debug("ERROR: failure to set option \"TrustedCerts\"\n");
        return;
    }

    // Successfully connected, so make sure the polling frequency is back to the default
    azureIoTPollPeriodSeconds = AzureIoTDefaultPollPeriodSeconds;
    struct timespec azureTelemetryPeriod = { azureIoTPollPeriodSeconds, 0 };
    SetTimerFdToPeriod(azureTimerFd, &azureTelemetryPeriod);

    iothubConnected = true;

    if (IoTHubDeviceClient_LL_SetOption(iothubClientHandle, OPTION_KEEP_ALIVE,
        &keepalivePeriodSeconds) != IOTHUB_CLIENT_OK) {
        Log_Debug("ERROR: failure setting option \"%s\"\n", OPTION_KEEP_ALIVE);
        return;
    }

    if (IoTHubDeviceClient_LL_SetDeviceTwinCallback(iothubClientHandle, TwinCallback, NULL) !=
        IOTHUB_CLIENT_OK) {
        Log_Debug("ERROR: failure setting option TwinCallback\n");
        return;
    }

    if (IoTHubDeviceClient_LL_SetConnectionStatusCallback(
        iothubClientHandle, HubConnectionStatusCallback, NULL) != IOTHUB_CLIENT_OK) {
        Log_Debug("ERROR: failure setting option HubConnectionStatusCallback\n");
        return;
    }

    // Set retry policy for the connection to the IoT Hub.
    if (IoTHubDeviceClient_LL_SetRetryPolicy(iothubClientHandle, IOTHUB_CLIENT_RETRY_INTERVAL,
        retryTimeoutSeconds) != IOTHUB_CLIENT_OK) {
        Log_Debug("ERROR: failure setting retry policy\n");
        return;
    }

    IoTHubDeviceClient_LL_DoWork(iothubClientHandle);
}

/// <summary>
///     Callback invoked when a Device Twin update is received from IoT Hub.
///     Updates local state for 'showEvents' (bool).
/// </summary>
/// <param name="payload">contains the Device Twin JSON document (desired and reported)</param>
/// <param name="payloadSize">size of the Device Twin JSON document</param>
static void TwinCallback(DEVICE_TWIN_UPDATE_STATE updateState, const unsigned char* payload,
    size_t payloadSize, void* userContextCallback)
{
    size_t nullTerminatedJsonSize = payloadSize + 1;
    char* nullTerminatedJsonString = (char*)malloc(nullTerminatedJsonSize);
    if (nullTerminatedJsonString == NULL) {
        Log_Debug("ERROR: Could not allocate buffer for twin update payload.\n");
        abort();
    }

    // Copy the provided buffer to a null terminated buffer.
    memcpy(nullTerminatedJsonString, payload, payloadSize);
    // Add the null terminator at the end.
    nullTerminatedJsonString[nullTerminatedJsonSize - 1] = 0;

    JSON_Value* rootProperties = NULL;
    rootProperties = json_parse_string(nullTerminatedJsonString);
    if (rootProperties == NULL) {
        Log_Debug("WARNING: Cannot parse the string as JSON content.\n");
        goto cleanup;
    }

    JSON_Object* rootObject = json_value_get_object(rootProperties);
    JSON_Object* desiredProperties = json_object_dotget_object(rootObject, "desired");
    if (desiredProperties == NULL) {
        desiredProperties = rootObject;
    }

    // Handle the Device Twin Desired Properties here.
    JSON_Object* LEDState = json_object_dotget_object(desiredProperties, "StatusLED");
    if (LEDState != NULL) {
        statusLedOn = (bool)json_object_get_boolean(LEDState, "value");
        GPIO_SetValue(deviceTwinStatusLedGpioFd,
            (statusLedOn == true ? GPIO_Value_Low : GPIO_Value_High));
        TwinReportBoolState("StatusLED", statusLedOn);
    }

    JSON_Object* OvenStartLEDState = json_object_dotget_object(desiredProperties, "RipleyOvenOnLED");
    if (OvenStartLEDState != NULL) {
        ovenLedOn = (bool)json_object_get_boolean(OvenStartLEDState, "value");
        GPIO_SetValue(deviceTwinRipleyLedGpioFd,
            (ovenLedOn == true ? GPIO_Value_Low : GPIO_Value_High));
        TwinReportBoolState("RipleyOvenOnLED", ovenLedOn);
    }

cleanup:
    // Release the allocated memory.
    json_value_free(rootProperties);
    free(nullTerminatedJsonString);
}

/// <summary>
///     Converts the IoT Hub connection status reason to a string.
/// </summary>
static const char* GetReasonString(IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason)
{
    static char* reasonString = "unknown reason";
    switch (reason) {
    case IOTHUB_CLIENT_CONNECTION_EXPIRED_SAS_TOKEN:
        reasonString = "IOTHUB_CLIENT_CONNECTION_EXPIRED_SAS_TOKEN";
        break;
    case IOTHUB_CLIENT_CONNECTION_DEVICE_DISABLED:
        reasonString = "IOTHUB_CLIENT_CONNECTION_DEVICE_DISABLED";
        break;
    case IOTHUB_CLIENT_CONNECTION_BAD_CREDENTIAL:
        reasonString = "IOTHUB_CLIENT_CONNECTION_BAD_CREDENTIAL";
        break;
    case IOTHUB_CLIENT_CONNECTION_RETRY_EXPIRED:
        reasonString = "IOTHUB_CLIENT_CONNECTION_RETRY_EXPIRED";
        break;
    case IOTHUB_CLIENT_CONNECTION_NO_NETWORK:
        reasonString = "IOTHUB_CLIENT_CONNECTION_NO_NETWORK";
        break;
    case IOTHUB_CLIENT_CONNECTION_COMMUNICATION_ERROR:
        reasonString = "IOTHUB_CLIENT_CONNECTION_COMMUNICATION_ERROR";
        break;
    case IOTHUB_CLIENT_CONNECTION_OK:
        reasonString = "IOTHUB_CLIENT_CONNECTION_OK";
        break;
    }
    return reasonString;
}

/// <summary>
///     Sends telemetry to IoT Hub
/// </summary>
/// <param name="key">The telemetry item to update</param>
/// <param name="value">new telemetry value</param>
static void SendTelemetry(const unsigned char* key, const unsigned char* value)
{
    static char eventBuffer[100] = { 0 };
    static const char* EventMsgTemplate = "{ \"%s\": \"%s\" }";
    int len = snprintf(eventBuffer, sizeof(eventBuffer), EventMsgTemplate, key, value);
    if (len < 0)
        return;

    Log_Debug("Sending IoT Hub Message: %s\n", eventBuffer);

    IOTHUB_MESSAGE_HANDLE messageHandle = IoTHubMessage_CreateFromString(eventBuffer);

    if (messageHandle == 0) {
        Log_Debug("WARNING: unable to create a new IoTHubMessage\n");
        return;
    }

    if (IoTHubDeviceClient_LL_SendEventAsync(iothubClientHandle, messageHandle, SendMessageCallback,
        /*&callback_param*/ 0) != IOTHUB_CLIENT_OK) {
        Log_Debug("WARNING: failed to hand over the message to IoTHubClient\n");
    }
    else {
        Log_Debug("INFO: IoTHubClient accepted the message for delivery\n");
    }

    IoTHubMessage_Destroy(messageHandle);
}

/// <summary>
///     Callback confirming message delivered to IoT Hub.
/// </summary>
/// <param name="result">Message delivery status</param>
/// <param name="context">User specified context</param>
static void SendMessageCallback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* context)
{
    Log_Debug("INFO - SendMessageCallback: Message received by IoT Hub. Result is: %d\n", result);
}

/// <summary>
///     Creates and enqueues a report containing the name and value pair of a Device Twin reported
///     property. The report is not sent immediately, but it is sent on the next invocation of
///     IoTHubDeviceClient_LL_DoWork().
/// </summary>
/// <param name="propertyName">the IoT Hub Device Twin property name</param>
/// <param name="propertyValue">the IoT Hub Device Twin property value</param>
static void TwinReportBoolState(const char* propertyName, bool propertyValue)
{
    if (iothubClientHandle == NULL) {
        Log_Debug("ERROR: client not initialized\n");
    }
    else {
        static char reportedPropertiesString[30] = { 0 };
        int len = snprintf(reportedPropertiesString, 30, "{\"%s\":%s}", propertyName,
            (propertyValue == true ? "true" : "false"));
        if (len < 0)
            return;

        if (IoTHubDeviceClient_LL_SendReportedState(
            iothubClientHandle, (unsigned char*)reportedPropertiesString,
            strlen(reportedPropertiesString), ReportStatusCallback, 0) != IOTHUB_CLIENT_OK) {
            Log_Debug("ERROR - IoTHubDeviceClient_LL_SendReportedState: failed to set reported state for '%s'.\n", propertyName);
        }
        else {
            Log_Debug("INFO - IoTHubDeviceClient_LL_SendReportedState: Reported state for '%s' to value '%s'.\n", propertyName,
                (propertyValue == true ? "true" : "false"));
        }
    }
}

/// <summary>
///     Callback invoked when the Device Twin reported properties are accepted by IoT Hub.
/// </summary>
static void ReportStatusCallback(int result, void* context)
{
    Log_Debug("INFO - ReportStatusCallback: Device Twin reported properties update result: HTTP status code %d\n", result);
}

/// <summary>
///     Generates a simulated Temperature and sends it to IoT Hub.
/// </summary>
void SendSimulatedTemperature(void)
{
    static float temperature = 30.0;
    float deltaTemp = (float)(rand() % 20) / 20.0f;
    if (rand() % 2 == 0) {
        temperature += deltaTemp;
    }
    else {
        temperature -= deltaTemp;
    }

    char tempBuffer[20];
    int len = snprintf(tempBuffer, 20, "%3.2f", temperature);
    if (len > 0)
        SendTelemetry("light", tempBuffer);
}

/// <summary>
///     Check whether a given button has just been pressed.
/// </summary>
/// <param name="fd">The button file descriptor</param>
/// <param name="oldState">Old state of the button (pressed or released)</param>
/// <returns>true if pressed, false otherwise</returns>
static bool IsButtonPressed(int fd, GPIO_Value_Type* oldState)
{
    bool isButtonPressed = false;
    GPIO_Value_Type newState;
    int result = GPIO_GetValue(fd, &newState);
    if (result != 0) {
        Log_Debug("ERROR: Could not read button GPIO: %s (%d).\n", strerror(errno), errno);
        terminationRequired = true;
    }
    else {
        // Button is pressed if it is low and different than last known state.
        isButtonPressed = (newState != *oldState) && (newState == GPIO_Value_Low);
        *oldState = newState;
    }

    return isButtonPressed;
}

/// <summary>
/// Pressing button A will:
///     Send a 'Button Pressed' event to Azure IoT Central
/// </summary>
static void SendMessageButtonHandler(void)
{
    if (IsButtonPressed(sendMessageButtonGpioFd, &sendMessageButtonState)) {
        SendTelemetry("ButtonPress", "True");
    }
}

/// <summary>
/// Pressing button B will:
///     Send an 'Orientation' event to Azure IoT Central
/// </summary>
static void SendOrientationButtonHandler(void)
{
    if (IsButtonPressed(sendOrientationButtonGpioFd, &sendOrientationButtonState)) {
        deviceIsUp = !deviceIsUp;
        SendTelemetry("Orientation", deviceIsUp ? "Up" : "Down");
    }
}
