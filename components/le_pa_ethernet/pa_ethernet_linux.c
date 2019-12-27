//--------------------------------------------------------------------------------------------------
/**
 * Linux Ethernet channel Adapter
 */
//--------------------------------------------------------------------------------------------------

#include "legato.h"
#include "pa_ethernet.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/rtnetlink.h>

//--------------------------------------------------------------------------------------------------
/**
 * Maximal length of a system command
 */
//--------------------------------------------------------------------------------------------------
#define MAX_SYSTEM_INPUT_LENGTH         256

//--------------------------------------------------------------------------------------------------
/**
 * Maximal length of a system command output
 */
//--------------------------------------------------------------------------------------------------
#define MAX_SYSTEM_OUTPUT_LENGTH        256

//--------------------------------------------------------------------------------------------------
/**
 * Maximal length of netlink payload
 */
//--------------------------------------------------------------------------------------------------
#define MAX_NL_PAYLOAD_LENGTH           2048

//--------------------------------------------------------------------------------------------------
/**
 * Command to retrieve Ethernet channels
 */
//--------------------------------------------------------------------------------------------------
#define COMMAND_READ_ETHERNET_CHANNEL   "/sbin/ifconfig | grep encap:Ethernet"

//--------------------------------------------------------------------------------------------------
/**
 * Command to retrieve technology from interface name
 */
//--------------------------------------------------------------------------------------------------
#define COMMAND_READ_INTERFACE_TECHNOLOGY   "/sbin/ifconfig %s | grep encap:Ethernet"

//--------------------------------------------------------------------------------------------------
/**
 * File to retrieve channel operstate
 */
//--------------------------------------------------------------------------------------------------
#define FILE_OF_CHANNEL_OPERSTATE   "/sys/class/net/%s/operstate"

//--------------------------------------------------------------------------------------------------
/**
 * WLAN interface prefix
 */
//--------------------------------------------------------------------------------------------------
#define WLAN_NAME_PREFIX   "wlan"

//--------------------------------------------------------------------------------------------------
/**
 * Brigde interface prefix
 */
//--------------------------------------------------------------------------------------------------
#define BRIDGE_NAME_PREFIX   "bridge"

//--------------------------------------------------------------------------------------------------
/**
 * This event is reported when an Ethernet interface status is updated.
 */
//--------------------------------------------------------------------------------------------------
static le_event_Id_t EthernetEventId;

//--------------------------------------------------------------------------------------------------
/**
 * Pool for Ethernet interface status indication reporting.
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t EthernetEventPool;

//--------------------------------------------------------------------------------------------------
/**
 * The netlink socket.
 */
//--------------------------------------------------------------------------------------------------
static int NetLinkSocket;

//--------------------------------------------------------------------------------------------------
/**
 * The socket address bound to netlink socket.
 */
//--------------------------------------------------------------------------------------------------
static struct sockaddr_nl SocketAddress;

//--------------------------------------------------------------------------------------------------
/**
 * Get technology from interface
 *
 * @return
 *      - LE_OK             Function succeeded
 *      - LE_BAD_PARAMETER  Invalid parameter
 *      - LE_FAULT          Function failed
 */
//--------------------------------------------------------------------------------------------------
static le_result_t GetTechFromInterface
(
    const char *interface        ///< [IN]  Interface name
)
{
    char    *outputReentrant;
    char    *interfaceName;
    FILE *fd = NULL;
    le_result_t result = LE_FAULT;
    char command[MAX_SYSTEM_INPUT_LENGTH] = {0};
    char output[MAX_SYSTEM_OUTPUT_LENGTH] = {0};

    if (NULL == interface)
    {
        LE_ERROR("Invalid parameter");
        return LE_BAD_PARAMETER;
    }

    snprintf(command, sizeof(command), COMMAND_READ_INTERFACE_TECHNOLOGY, interface);
    fd = popen(command, "r");

    if (NULL == fd)
    {
        LE_ERROR("Failed to run command:\"%s\" errno:%d %s",
                 command, errno, LE_ERRNO_TXT(errno));
        return result;
    }

    while (NULL != fgets(output, sizeof(output)-1, fd))
    {
        // Retrieve interface name
        outputReentrant = output;
        interfaceName = strtok_r(outputReentrant, " ", &outputReentrant);
        if (NULL == interfaceName)
        {
            LE_DEBUG("Failed to retrieve interface");
        }
        else
        {
            // WLAN and bridge interface reported as Ethernet in ifconfig, skip them
            if (NULL == strstr(interfaceName, WLAN_NAME_PREFIX) &&
                NULL == strstr(interfaceName, BRIDGE_NAME_PREFIX))
            {
                result = LE_OK;
            }
        }
    }

    pclose(fd);
    return result;
}

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
le_result_t pa_ethernet_GetInterfaceState
(
    const char *interface,        ///< [IN]  Interface name
    le_dcs_State_t *state         ///< [INOUT] Interface state down/up
)
{
    FILE *fd = NULL;
    char fileName[MAX_SYSTEM_INPUT_LENGTH] = {0};
    char output[MAX_SYSTEM_OUTPUT_LENGTH] = {0};

    if ((NULL == interface) || (NULL == state))
    {
        LE_ERROR("Invalid parameter");
        return LE_BAD_PARAMETER;
    }

    *state = LE_DCS_STATE_DOWN;
    snprintf(fileName, sizeof(fileName), FILE_OF_CHANNEL_OPERSTATE, interface);
    fd = fopen(fileName, "r");

    if (NULL == fd)
    {
        LE_ERROR("Failed to open file :\"%s\"", fileName);
        return LE_FAULT;
    }

    // Retrieve output
    while (NULL != fgets(output, sizeof(output)-1, fd))
    {
        if (strstr(output, "up"))
        {
            *state = LE_DCS_STATE_UP;
        }
    }

    fclose(fd);
    LE_DEBUG("Interface %s in state %s", interface, (*state == LE_DCS_STATE_UP) ? "up" : "down");
    return LE_OK;
}

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
le_result_t pa_ethernet_GetChannelList
(
    le_dcs_ChannelInfo_t* channelList, ///< [INOUT] List of available Ethernet channels
    size_t* listSize                   ///< [INOUT] List size
)
{
    char    *interfaceName;
    char    *outputReentrant;
    char    output[MAX_SYSTEM_OUTPUT_LENGTH];
    le_result_t result;
    int     listIndex = 0;
    FILE    *fd = NULL;

    if ((NULL == channelList) || (NULL == listSize))
    {
        LE_ERROR("Invalid parameter");
        return LE_BAD_PARAMETER;
    }

    fd = popen(COMMAND_READ_ETHERNET_CHANNEL, "r");

    if (NULL == fd)
    {
        LE_ERROR("Failed to run command:\"%s\" errno:%d %s",
                 COMMAND_READ_ETHERNET_CHANNEL,
                 errno,
                 LE_ERRNO_TXT(errno));
        return LE_FAULT;
    }

    while (NULL != fgets(output, sizeof(output)-1, fd))
    {
        LE_DEBUG("PARSING:%s: len:%d", output, (int) strnlen(output, sizeof(output) - 1));
        // Retrieve Ethernet interface name
        outputReentrant = output;
        interfaceName = strtok_r(outputReentrant, " ", &outputReentrant);
        if (NULL == interfaceName)
        {
            LE_DEBUG("Failed to retrieve Ethernet interface");
        }
        else
        {
            // WLAN and bridge interface reported as Ethernet in ifconfig, skip them
            if (NULL == strstr(interfaceName, WLAN_NAME_PREFIX) &&
                NULL == strstr(interfaceName, BRIDGE_NAME_PREFIX))
            {
                le_utf8_Copy(channelList[listIndex].name, interfaceName,
                             sizeof(channelList[listIndex].name), NULL);
                channelList[listIndex].technology = LE_DCS_TECH_ETHERNET;
                result = pa_ethernet_GetInterfaceState(channelList[listIndex].name,
                                                       &channelList[listIndex].state);
                if (LE_OK != result)
                {
                    LE_DEBUG("Failed to get state of channel %s", channelList[listIndex].name);
                }
                listIndex ++;
                if (LE_DCS_CHANNEL_LIST_QUERY_MAX <= listIndex)
                {
                    LE_DEBUG("No space to add more channels");
                    break;
                }
            }
        }
    }

    pclose(fd);
    *listSize = (listIndex < *listSize) ? listIndex : *listSize;

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * The first-layer Ethernet Event Indication Handler.
 *
 */
//--------------------------------------------------------------------------------------------------
static void FirstLayerEthernetEventIndHandler
(
    void *reportPtr,
    void *secondLayerHandlerFuncPtr
)
{
    pa_ethernet_EventIndHandlerFunc_t  clientHandlerFunc = secondLayerHandlerFuncPtr;
    le_dcs_ChannelInfo_t*  ethernetChannelInfoPtr = reportPtr;

    if (NULL != ethernetChannelInfoPtr)
    {
        LE_DEBUG("Ethernet event: interface: %s, technology: %d, state: %d",
                 ethernetChannelInfoPtr->name,
                 ethernetChannelInfoPtr->technology,
                 ethernetChannelInfoPtr->state);

        clientHandlerFunc(ethernetChannelInfoPtr, le_event_GetContextPtr());
    }
    else
    {
        LE_ERROR("ethernetChannelInfoPtr is NULL");
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Add handler function for PA Ethernet channel event
 *
 * This event provide information on PA Ethernet event changes.
 *
 * @return LE_BAD_PARAMETER  The function failed due to an invalid parameter.
 * @return LE_OK             The function succeeded.
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_ethernet_AddEventIndHandler
(
    pa_ethernet_EventIndHandlerFunc_t handlerPtr,
        ///< [IN]
        ///< Event handler function pointer.

    void *contextPtr
        ///< [IN]
        ///< Associated event context.
)
{
    le_event_HandlerRef_t handlerRef;

    handlerRef = le_event_AddLayeredHandler("EthernetPaHandler",
                                            EthernetEventId,
                                            FirstLayerEthernetEventIndHandler,
                                            (le_event_HandlerFunc_t)handlerPtr);
    if (NULL == handlerRef)
    {
        LE_ERROR("le_event_AddLayeredHandler returned NULL");
        return LE_BAD_PARAMETER;
    }
    le_event_SetContextPtr(handlerRef, contextPtr);
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * PA netlink message handler
 */
//--------------------------------------------------------------------------------------------------
static void LinkStateUpdate
(
    struct nlmsghdr *netlinkHeader
)
{
    struct ifinfomsg *ifInfo;

    ifInfo = NLMSG_DATA(netlinkHeader);

    le_dcs_ChannelInfo_t* ethernetChannelInfoPtr = le_mem_ForceAlloc(EthernetEventPool);
    memset(ethernetChannelInfoPtr, 0, sizeof(le_dcs_ChannelInfo_t));

    if_indextoname(ifInfo->ifi_index, ethernetChannelInfoPtr->name);
    ethernetChannelInfoPtr->technology = LE_DCS_TECH_ETHERNET;
    ethernetChannelInfoPtr->state = (ifInfo->ifi_flags & IFF_RUNNING) ?
                                  LE_DCS_STATE_UP : LE_DCS_STATE_DOWN;

    LE_DEBUG("netlink_link_state: Link %s %s\n", ethernetChannelInfoPtr->name,
             (ethernetChannelInfoPtr->state == LE_DCS_STATE_UP) ? "Up" : "Down");

    le_event_ReportWithRefCounting(EthernetEventId, ethernetChannelInfoPtr);
}

//--------------------------------------------------------------------------------------------------
/**
 * PA netlink message handler
 */
//--------------------------------------------------------------------------------------------------
static void NetMsgHandler
(
    struct nlmsghdr *netlinkHeader
)
{
    char    ifname[LE_DCS_INTERFACE_NAME_MAX_LEN] = {0};
    struct  ifinfomsg *ifInfo = NLMSG_DATA(netlinkHeader);
    struct  ifaddrmsg *ifAddr = NLMSG_DATA(netlinkHeader);

    switch (netlinkHeader->nlmsg_type)
    {
        case RTM_NEWADDR:
            if_indextoname(ifInfo->ifi_index, ifname);
            LE_DEBUG("Netlink handler: RTM_NEWADDR : %s", ifname);
            break;

        case RTM_DELADDR:
            if_indextoname(ifInfo->ifi_index, ifname);
            LE_DEBUG("Netlink handler: RTM_DELADDR : %s", ifname);
            break;

        case RTM_NEWLINK:
            if_indextoname(ifAddr->ifa_index, ifname);
            //Skip event with empty interface name
            if (ifname[0] != '\0')
            {
                if (LE_OK == GetTechFromInterface(ifname))
                {
                    LinkStateUpdate(netlinkHeader);
                }
            }
            break;

        case RTM_DELLINK:
            if_indextoname(ifAddr->ifa_index, ifname);
            LE_DEBUG("Netlink handler: RTM_DELLINK : %s", ifname);
            break;

        default:
            LE_DEBUG("Netlink handler: Unknown netlink nlmsg type %d",
                     netlinkHeader->nlmsg_type);
            break;
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Handler function of netlink socket monitor
 */
//--------------------------------------------------------------------------------------------------
static void NetlinkSocketHandler
(
    int NetLinkSocket,
    short events
)
{
    int     len;
    char    buf[MAX_NL_PAYLOAD_LENGTH];
    struct  nlmsghdr *netlinkHeader;
    struct  iovec iov = { (void*)buf, sizeof(buf) };
    struct  msghdr msg = { (void*)&SocketAddress, sizeof(SocketAddress), &iov, 1, NULL, 0, 0 };

    // Check data availability
    if (events & POLLIN)
    {
        len = recvmsg(NetLinkSocket, &msg, 0);

        if (0 > len)
        {
            LE_ERROR("read_netlink: Error in recvmsg, length is %d", len);
            return;
        }
        if (0 == len)
        {
            LE_DEBUG("read_netlink: EOF");
        }

        for (netlinkHeader = (struct nlmsghdr *) buf; NLMSG_OK (netlinkHeader, len);
             netlinkHeader = NLMSG_NEXT (netlinkHeader, len))
        {
            if (NLMSG_DONE == netlinkHeader->nlmsg_type)
            {
                break;
            }
            if (NLMSG_ERROR == netlinkHeader->nlmsg_type)
            {
                LE_ERROR("read_netlink: NLMSG_ERROR");
                break;
            }
            //Call netlink message handler
            NetMsgHandler(netlinkHeader);
        }
    }

    return;
}

//--------------------------------------------------------------------------------------------------
/**
 * Funtion to create netlink socket and socket monitor
 * @return
 *      - LE_OK             Function successful
 *      - LE_FAULT          Function failed
 */
//--------------------------------------------------------------------------------------------------
static le_result_t NetlinkSocketInit
(
    void
)
{
    int ret;

    NetLinkSocket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (NetLinkSocket == -1)
    {
        LE_ERROR("Failed to create socket for Ethernet event: %s", LE_ERRNO_TXT(errno));
        return LE_FAULT;
    }

    memset(&SocketAddress, 0, sizeof(SocketAddress));
    SocketAddress.nl_family = AF_NETLINK;
    SocketAddress.nl_pid = getpid();
    SocketAddress.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    ret = bind(NetLinkSocket, (struct sockaddr*) &SocketAddress, sizeof(SocketAddress));
    if (ret == -1)
    {
        LE_ERROR("Failed to bind netlink socket: %s", LE_ERRNO_TXT(errno));
        close(NetLinkSocket);
        return LE_FAULT;
    }

    // Create a File Descriptor Monitor object for the netlink socket.
    // Monitor for data available to read.
    le_fdMonitor_Ref_t fdMonitor = le_fdMonitor_Create("Netlink Socket",
                                                       NetLinkSocket,
                                                       NetlinkSocketHandler,
                                                       POLLIN);
    if (!fdMonitor)
    {
        LE_ERROR("Failed to create monitor for netlink socket");
        close(NetLinkSocket);
        return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Component init
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
    EthernetEventId = le_event_CreateIdWithRefCounting("EthernetEvent");
    EthernetEventPool = le_mem_CreatePool("EthernetEventPool",
                                          sizeof(le_dcs_ChannelInfo_t));

    if (LE_OK != NetlinkSocketInit())
    {
        LE_ERROR("Failed to initialize netlink socket");
    }
    else
    {
        LE_INFO("PA Ethernet component is ready");
    }
}
