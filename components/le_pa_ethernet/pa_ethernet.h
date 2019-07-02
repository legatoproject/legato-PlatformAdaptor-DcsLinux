/**
 * @page pa_ethernet Data Connection Service Adapter API
 *
 * @ref pa_ethernet.h "API Reference"
 *
 * <HR>
 *
 * @section pa_ethernet_toc Table of Contents
 *
 *  - @ref pa_ethernet_intro
 *  - @ref pa_ethernet_rational
 *
 *
 * @section pa_ethernet_intro Introduction
 *
 * As Sierra Wireless is moving into supporting multiple OS platforms,
 * we need to abstract Data Connection Services layer
 *
 * <HR>
 *
 * Copyright (C) Sierra Wireless Inc.
 */


#ifndef LEGATO_PA_ETHERNET_INCLUDE_GUARD
#define LEGATO_PA_ETHERNET_INCLUDE_GUARD

#include "legato.h"
#include "interfaces.h"

//--------------------------------------------------------------------------------------------------
/**
 * Event handler for PA Ethernet channel event changes.
 *
 * Handles the PA Ethernet channel events.
 */
//--------------------------------------------------------------------------------------------------
typedef void (*pa_ethernet_EventIndHandlerFunc_t)
(
    le_dcs_ChannelInfo_t* ethernetChannelInfoPtr,
        ///< [IN]
        ///< Ethernet channel event pointer to process
    void *contextPtr
        ///< [IN]
        ///< Associated Ethernet channel event context
);

//--------------------------------------------------------------------------------------------------
/**
 * Add handler function for PA Ethernet channel events
 *
 * This event provide information on PA Ethernet event changes.
 *
 * @return LE_BAD_PARAMETER  The function failed due to an invalid parameter.
 * @return LE_OK             The function succeeded.
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_ethernet_AddEventIndHandler
(
    pa_ethernet_EventIndHandlerFunc_t handlerPtr,
        ///< [IN]
        ///< Event handler function pointer.
    void *contextPtr
        ///< [IN]
        ///< Associated event context.
);

//--------------------------------------------------------------------------------------------------
/**
 * Query for a connection's network interface state
 *
 * @return
 *      - LE_OK             Function succeeded
 *      - LE_BAD_PARAMETER  Invalid parameter
 *      - LE_FAULT          Function failed
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_ethernet_GetInterfaceState
(
    const char *interface,        ///< [IN]  Interface name
    le_dcs_State_t *statePtr      ///< [INOUT] Interface state down/up
);

//--------------------------------------------------------------------------------------------------
/**
 * Query for Ethernet channels
 *
 * @return
 *      - LE_OK             Function succeeded
 *      - LE_BAD_PARAMETER  Invalid parameter
 *      - LE_FAULT          Function failed
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_ethernet_GetChannelList
(
    le_dcs_ChannelInfo_t* channelList, ///< [INOUT] List of available Ethernet channels
    size_t* listSize                   ///< [INOUT] List size
);

#endif
