//--------------------------------------------------------------------------------------------------
/**
 * Linux Data Connection Service Adapter
 * Provides adapter for linux specific functionality needed by
 * dataConnectionService component
 *
 */
//--------------------------------------------------------------------------------------------------

#include "legato.h"
#include "interfaces.h"
#include "pa_dcs.h"
#include <arpa/inet.h>
#include <time.h>


//--------------------------------------------------------------------------------------------------
/**
 * Maximal length of a system command
 */
//--------------------------------------------------------------------------------------------------
#define MAX_SYSTEM_CMD_LENGTH           512

//--------------------------------------------------------------------------------------------------
/**
 * Maximal length of a system command output
 */
//--------------------------------------------------------------------------------------------------
#define MAX_SYSTEM_CMD_OUTPUT_LENGTH    1024

//--------------------------------------------------------------------------------------------------
/**
 * Maximal length of an IPv4/v6 address
 */
//--------------------------------------------------------------------------------------------------
#define IPADDR_MAX_LEN 46

//--------------------------------------------------------------------------------------------------
/**
 * The linux system file to read for default gateway
 */
//--------------------------------------------------------------------------------------------------
#define ROUTE_FILE "/proc/net/route"

//--------------------------------------------------------------------------------------------------
/**
 * Buffer to store resolv.conf cache
 */
//--------------------------------------------------------------------------------------------------
static char ResolvConfBuffer[256];

//--------------------------------------------------------------------------------------------------
/**
 * Read DNS configuration from /etc/resolv.conf
 *
 * @return File content in a statically allocated string (shouldn't be freed)
 */
//--------------------------------------------------------------------------------------------------
static char* ReadResolvConf
(
    void
)
{
    int   fd;
    char* fileContentPtr = NULL;
    off_t fileSz;

    fd = open("/etc/resolv.conf", O_RDONLY);
    if (fd < 0)
    {
        LE_WARN("fopen on /etc/resolv.conf failed");
        return NULL;
    }

    fileSz = lseek(fd, 0, SEEK_END);
    LE_FATAL_IF( (fileSz < 0), "Unable to get resolv.conf size" );

    if (0 != fileSz)
    {

        LE_DEBUG("Caching resolv.conf: size[%lx]", fileSz);

        lseek(fd, 0, SEEK_SET);

        if (fileSz > (sizeof(ResolvConfBuffer) - 1))
        {
            LE_ERROR("Buffer is too small (%zu), file will be truncated from %lx",
                    sizeof(ResolvConfBuffer), fileSz);
            fileSz = sizeof(ResolvConfBuffer) - 1;
        }

        fileContentPtr = ResolvConfBuffer;

        if (0 > read(fd, fileContentPtr, fileSz))
        {
            LE_ERROR("Caching resolv.conf failed");
            fileContentPtr[0] = '\0';
            fileSz = 0;
        }
        else
        {
            fileContentPtr[fileSz] = '\0';
        }
    }

    if (0 != close(fd))
    {
        LE_FATAL("close failed");
    }

    LE_FATAL_IF(fileContentPtr && (strlen(fileContentPtr) > fileSz),
                "Content size (%zu) and File size (%lx) differ",
                strlen(fileContentPtr), fileSz );

    return fileContentPtr;
}

//--------------------------------------------------------------------------------------------------
/**
 * Remove the DNS configuration from /etc/resolv.conf
 *
 * @return
 *      LE_FAULT        Function failed
 *      LE_OK           Function succeed
 */
//--------------------------------------------------------------------------------------------------
static le_result_t RemoveNameserversFromResolvConf
(
    const char*  dns1Ptr,    ///< [IN] Pointer on first DNS address
    const char*  dns2Ptr     ///< [IN] Pointer on second DNS address
)
{
    char* resolvConfSourcePtr = ReadResolvConf();
    char* currentLinePtr = resolvConfSourcePtr;
    int currentLinePos = 0;

    FILE*  resolvConfPtr;
    mode_t oldMask;

    if (NULL == resolvConfSourcePtr)
    {
        // Nothing to remove
        return LE_OK;
    }

    // allow fopen to create file with mode=644
    oldMask = umask(022);

    resolvConfPtr = fopen("/etc/resolv.conf", "w");

    if (NULL == resolvConfPtr)
    {
        // restore old mask
        umask(oldMask);

        LE_WARN("fopen on /etc/resolv.conf failed");
        return LE_FAULT;
    }

    // For each line in source file
    while (true)
    {
        if (   ('\0' == currentLinePtr[currentLinePos])
            || ('\n' == currentLinePtr[currentLinePos])
           )
        {
            char sourceLineEnd = currentLinePtr[currentLinePos];
            currentLinePtr[currentLinePos] = '\0';

            // Got to the end of the source file
            if ('\0' == (sourceLineEnd) && (0 == currentLinePos))
            {
                break;
            }

            // If line doesn't contains an entry to remove,
            // copy line to new content
            if (   (NULL == strstr(currentLinePtr, dns1Ptr))
                && (NULL == strstr(currentLinePtr, dns2Ptr))
               )
            {
                // The original file contents may not have the final line terminated by
                // a new-line; always terminate with a new-line, since this is what is
                // usually expected on linux.
                currentLinePtr[currentLinePos] = '\n';
                fwrite(currentLinePtr, sizeof(char), (currentLinePos+1), resolvConfPtr);
            }


            if ('\0' == sourceLineEnd)
            {
                // This should only occur if the last line was not terminated by a new-line.
                break;
            }
            else
            {
                currentLinePtr += (currentLinePos+1); // Next line
                currentLinePos = 0;
            }
        }
        else
        {
            currentLinePos++;
        }
    }

    // restore old mask
    umask(oldMask);

    if (0 != fclose(resolvConfPtr))
    {
        LE_WARN("fclose failed");
        return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Write the DNS configuration into /etc/resolv.conf
 *
 * @return
 *      LE_FAULT        Function failed
 *      LE_OK           Function succeed
 */
//--------------------------------------------------------------------------------------------------
static le_result_t AddNameserversToResolvConf
(
    const char* dns1Ptr,    ///< [IN] Pointer on first DNS address
    const char* dns2Ptr     ///< [IN] Pointer on second DNS address
)
{
    bool addDns1 = true;
    bool addDns2 = true;

    LE_INFO("Set DNS '%s' '%s'", dns1Ptr, dns2Ptr);

    addDns1 = ('\0' != dns1Ptr[0]);
    addDns2 = ('\0' != dns2Ptr[0]);

    // Look for entries to add in the existing file
    char* resolvConfSourcePtr = ReadResolvConf();

    if (NULL != resolvConfSourcePtr)
    {
        char* currentLinePtr = resolvConfSourcePtr;
        int currentLinePos = 0;

        // For each line in source file
        while (true)
        {
            if (   ('\0' == currentLinePtr[currentLinePos])
                || ('\n' == currentLinePtr[currentLinePos])
               )
            {
                char sourceLineEnd = currentLinePtr[currentLinePos];
                currentLinePtr[currentLinePos] = '\0';

                if (NULL != strstr(currentLinePtr, dns1Ptr))
                {
                    LE_DEBUG("DNS 1 '%s' found in file", dns1Ptr);
                    addDns1 = false;
                }
                else if (NULL != strstr(currentLinePtr, dns2Ptr))
                {
                    LE_DEBUG("DNS 2 '%s' found in file", dns2Ptr);
                    addDns2 = false;
                }

                if ('\0' == sourceLineEnd)
                {
                    break;
                }
                else
                {
                    currentLinePtr[currentLinePos] = sourceLineEnd;
                    currentLinePtr += (currentLinePos+1); // Next line
                    currentLinePos = 0;
                }
            }
            else
            {
                currentLinePos++;
            }
        }
    }

    if (!addDns1 && !addDns2)
    {
        // No need to change the file
        return LE_OK;
    }

    FILE*  resolvConfPtr;
    mode_t oldMask;

    // allow fopen to create file with mode=644
    oldMask = umask(022);

    resolvConfPtr = fopen("/etc/resolv.conf", "w");
    if (NULL == resolvConfPtr)
    {
        // restore old mask
        umask(oldMask);

        LE_WARN("fopen on /etc/resolv.conf failed");
        return LE_FAULT;
    }

    // Set DNS 1 if needed
    if (addDns1 && (fprintf(resolvConfPtr, "nameserver %s\n", dns1Ptr) < 0))
    {
        // restore old mask
        umask(oldMask);

        LE_WARN("fprintf failed");
        if (0 != fclose(resolvConfPtr))
        {
            LE_WARN("fclose failed");
        }
        return LE_FAULT;
    }

    // Set DNS 2 if needed
    if (addDns2 && (fprintf(resolvConfPtr, "nameserver %s\n", dns2Ptr) < 0))
    {
        // restore old mask
        umask(oldMask);

        LE_WARN("fprintf failed");
        if (0 != fclose(resolvConfPtr))
        {
            LE_WARN("fclose failed");
        }
        return LE_FAULT;
    }

    // Append rest of the file
    if (NULL != resolvConfSourcePtr)
    {
        size_t writeLen = strlen(resolvConfSourcePtr);

        if (writeLen != fwrite(resolvConfSourcePtr, sizeof(char), writeLen, resolvConfPtr))
        {
            // restore old mask
            umask(oldMask);

            LE_CRIT("Writing resolv.conf failed");
            if (0 != fclose(resolvConfPtr))
            {
                LE_WARN("fclose failed");
            }
            return LE_FAULT;
        }
    }

    // restore old mask
    umask(oldMask);

    if (0 != fclose(resolvConfPtr))
    {
        LE_WARN("fclose failed");
        return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the DNS configuration
 *
 * @return
 *      LE_FAULT        Function failed
 *      LE_OK           Function succeed
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_SetDnsNameServers
(
    const char* dns1Ptr,    ///< [IN] Pointer on first DNS address
    const char* dns2Ptr     ///< [IN] Pointer on second DNS address
)
{
    return AddNameserversToResolvConf(dns1Ptr, dns2Ptr);
}

//--------------------------------------------------------------------------------------------------
/**
 * Asks (DHCP server) for IP address
 *
 * @return
 *      - LE_OK     Function successful
 *      - LE_FAULT  Function failed
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_AskForIpAddress
(
    const char*    interfaceStrPtr
)
{
    int16_t systemResult;
    char systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};

    // DHCP Client
    snprintf(systemCmd,
             sizeof(systemCmd),
             "PATH=/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin;"
             "/sbin/udhcpc -R -b -i %s",
             interfaceStrPtr
            );

    systemResult = system(systemCmd);
    // Return value of -1 means that the fork() has failed (see man system)
    if (0 == WEXITSTATUS(systemResult))
    {
        LE_INFO("DHCP client successful!");
        return LE_OK;
    }
    else
    {
        LE_ERROR("DHCP client failed: command %s, result %d", systemCmd, systemResult);
        return LE_FAULT;
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Executes change route
 *
 * return
 *      LE_OK           Function succeed
 *      LE_FAULT        Function failed
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_ChangeRoute
(
    pa_dcs_RouteAction_t   routeAction,
    const char*            ipDestAddrStrPtr,
    const char*            ipDestMaskStrPtr,
    const char*            interfaceStrPtr
)
{
    const char optionPtr[] = "-A inet";
    char actionStr[MAX_SYSTEM_CMD_LENGTH] = {0};
    char systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};
    char destMaskStr[IPADDR_MAX_LEN] = {0};
    char *addNetStr = "";

    switch (routeAction)
    {
        case PA_DCS_ROUTE_ADD:
            snprintf(actionStr, sizeof(actionStr), "add");
            break;

        case PA_DCS_ROUTE_DELETE:
            snprintf(actionStr, sizeof(actionStr), "del");
            break;

        default:
            LE_ERROR("Unknown action %d", (uint16_t)routeAction);
            return LE_FAULT;
    }

    if (strlen(ipDestMaskStrPtr) > 0)
    {
        addNetStr = "-net";
        snprintf(destMaskStr, sizeof(destMaskStr), "netmask %s", ipDestMaskStrPtr);
    }

    // The command line to be formulated below will look like this for adding a route:
    // When ipDestMaskStrPtr is a null string, it'll be adding a host route and the command is:
    //     /sbin/route -A inet add <addr> dev <interface>
    //
    // When ipDestMaskStrPtr is not null, it'll be adding a network route and the command becomes:
    //     /sbin/route -A inet add -net <addr> netmask <mask> dev <interface>
    //
    snprintf(systemCmd, sizeof(systemCmd), "/sbin/route %s %s %s %s %s dev %s",
             optionPtr, actionStr, addNetStr, ipDestAddrStrPtr, destMaskStr, interfaceStrPtr);
    LE_DEBUG("Execute '%s'", systemCmd);
    if (-1 == system(systemCmd))
    {
        LE_WARN("system '%s' failed", systemCmd);
        return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the default gateway in the system
 *
 * return
 *      LE_OK           Function succeed
 *      LE_FAULT        Function failed
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_SetDefaultGateway
(
    const char* interfacePtr,   ///< [IN] Pointer on the interface name
    const char* gatewayPtr,     ///< [IN] Pointer on the gateway name
    bool        isIpv6          ///< [IN] IPv6 or not
)
{
    const char* optionPtr = "";
    char        systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};

    if ((0 == strcmp(gatewayPtr, "")) || (0 == strcmp(interfacePtr, "")))
    {
        LE_WARN("Default gateway or interface is empty");
        return LE_FAULT;
    }

    if (LE_OK != pa_dcs_DeleteDefaultGateway())
    {
        LE_ERROR("Unable to delete default gateway");
        return LE_FAULT;
    }

    LE_DEBUG("Try set the gateway '%s' on '%s'", gatewayPtr, interfacePtr);

    if (isIpv6)
    {
        optionPtr = "-A inet6";
    }

    // TODO: use of ioctl instead, should be done when rework the DCS
    snprintf(systemCmd, sizeof(systemCmd), "/sbin/route %s add default gw %s %s",
             optionPtr, gatewayPtr, interfacePtr);
    LE_DEBUG("Execute '%s'", systemCmd);
    if (-1 == system(systemCmd))
    {
        LE_WARN("system '%s' failed", systemCmd);
        return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Save the default route into the input data structure provided
 * ToDo: Need to add code to support IPv6 default GW
 *
 * @return
 *     - LE_OK if the retrieval of default GW address(es) has been successful
 *     - LE_NOT_FOUND if no currently set default GW address has been found
 *     - LE_FAULT if the attempt to retrieve has failed
 *     - LE_OVERFLOW if the address to be retrieved has exceeded in length the provided buffer's
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_GetDefaultGateway
(
    pa_dcs_InterfaceDataBackup_t* interfaceDataBackupPtr
)
{
    le_result_t result;
    FILE*       routeFile;
    char        line[100] , *ifacePtr , *destPtr, *gwPtr, *saveptr;

    routeFile = le_flock_OpenStream(ROUTE_FILE, LE_FLOCK_READ, &result);

    if (NULL == routeFile)
    {
        LE_ERROR("Could not open file %s", ROUTE_FILE);
        return LE_FAULT;
    }

    // Initialize default value
    interfaceDataBackupPtr->defaultInterface[0] = '\0';
    interfaceDataBackupPtr->defaultGateway[0]   = '\0';

    result = LE_NOT_FOUND;

    while (fgets(line, sizeof(line), routeFile))
    {
        ifacePtr = strtok_r(line, " \t", &saveptr);
        destPtr  = strtok_r(NULL, " \t", &saveptr);
        gwPtr    = strtok_r(NULL, " \t", &saveptr);

        if ((NULL != ifacePtr) && (NULL != destPtr))
        {
            if (0 == strcmp(destPtr , "00000000"))
            {
                if (gwPtr)
                {
                    char*    pEnd;
                    uint32_t ng=strtoul(gwPtr,&pEnd,16);
                    struct in_addr addr;
                    addr.s_addr=ng;

                    result = le_utf8_Copy(
                               interfaceDataBackupPtr->defaultInterface,
                               ifacePtr,
                               sizeof(interfaceDataBackupPtr->defaultInterface),
                               NULL);
                    if (result != LE_OK)
                    {
                        LE_WARN("interface buffer is too small");
                        break;
                    }

                    result = le_utf8_Copy(
                                 interfaceDataBackupPtr->defaultGateway,
                                 inet_ntoa(addr),
                                 sizeof(interfaceDataBackupPtr->defaultGateway),
                                 NULL);
                    if (result != LE_OK)
                    {
                        LE_WARN("gateway buffer is too small");
                        break;
                    }
                }
                break;
            }
        }
    }

    le_flock_CloseStream(routeFile);

    switch (result)
    {
        case LE_OK:
            LE_DEBUG("default gateway is: '%s' on '%s'",
                     interfaceDataBackupPtr->defaultGateway,
                     interfaceDataBackupPtr->defaultInterface);
            break;

        case LE_NOT_FOUND:
            LE_DEBUG("No default gateway to retrieve");
            break;

        default:
            LE_WARN("Could not retrieve the default gateway");
            break;
    }
    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Check if a default gateway is set
 *
 * @return
 *      True or False
 */
//--------------------------------------------------------------------------------------------------
static bool IsDefaultGatewayPresent
(
    void
)
{
    pa_dcs_InterfaceDataBackup_t backup;
    return (LE_OK == pa_dcs_GetDefaultGateway(&backup));
}

//--------------------------------------------------------------------------------------------------
/**
 * Delete the default gateway in the system, if it is present
 *
 * return
 *      LE_OK           Function succeed
 *      LE_FAULT        Function failed
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_DeleteDefaultGateway
(
    void
)
{
    char systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};

    if (IsDefaultGatewayPresent())
    {
        le_result_t v4Ret = LE_OK, v6Ret = LE_OK;
        // Remove the last IPv4 default GW
        snprintf(systemCmd, sizeof(systemCmd), "/sbin/route del default");
        LE_DEBUG("Execute '%s'", systemCmd);
        if (-1 == system(systemCmd))
        {
            LE_WARN("system '%s' failed", systemCmd);
            v4Ret = LE_FAULT;
        }

        // Remove the last IPv6 default GW
        snprintf(systemCmd, sizeof(systemCmd), "/sbin/route -A inet6 del default");
        LE_DEBUG("Execute '%s'", systemCmd);
        if (-1 == system(systemCmd))
        {
            LE_WARN("system '%s' failed", systemCmd);
            v6Ret = LE_FAULT;
        }

        // Return fault if both none of IPv4 and IPv6 default GW config deletions succeeded
        if ((v4Ret != LE_OK) && (v6Ret != LE_OK))
        {
            return LE_FAULT;
        }
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Used the data backup upon connection to remove DNS entries locally added
 */
//--------------------------------------------------------------------------------------------------
void pa_dcs_RestoreInitialDnsNameServers
(
    pa_dcs_InterfaceDataBackup_t* interfaceDataBackupPtr
)
{
    if (   ('\0' != interfaceDataBackupPtr->newDnsIPv4[0][0])
        || ('\0' != interfaceDataBackupPtr->newDnsIPv4[1][0])
       )
    {
        LE_DEBUG("Removing IPv4 DNS server addresses %s & %s from device",
                 interfaceDataBackupPtr->newDnsIPv4[0],
                 interfaceDataBackupPtr->newDnsIPv4[1]);
        RemoveNameserversFromResolvConf(
                                 interfaceDataBackupPtr->newDnsIPv4[0],
                                 interfaceDataBackupPtr->newDnsIPv4[1]);

        // Delete backed up data
        memset(interfaceDataBackupPtr->newDnsIPv4[0], '\0',
               sizeof(interfaceDataBackupPtr->newDnsIPv4[0]));
        memset(interfaceDataBackupPtr->newDnsIPv4[1], '\0',
               sizeof(interfaceDataBackupPtr->newDnsIPv4[1]));
    }

    if (   ('\0' != interfaceDataBackupPtr->newDnsIPv6[0][0])
        || ('\0' != interfaceDataBackupPtr->newDnsIPv6[1][0])
       )
    {
        LE_DEBUG("Removing IPv6 DNS server addresses %s & %s from device",
                 interfaceDataBackupPtr->newDnsIPv6[0],
                 interfaceDataBackupPtr->newDnsIPv6[1]);
        RemoveNameserversFromResolvConf(
                                 interfaceDataBackupPtr->newDnsIPv6[0],
                                 interfaceDataBackupPtr->newDnsIPv6[1]);

        // Delete backed up data
        memset(interfaceDataBackupPtr->newDnsIPv6[0], '\0',
               sizeof(interfaceDataBackupPtr->newDnsIPv6[0]));
        memset(interfaceDataBackupPtr->newDnsIPv6[1], '\0',
               sizeof(interfaceDataBackupPtr->newDnsIPv6[1]));
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Retrieve time from a server using the Time Protocol.
 *
 * @return
 *      - LE_OK             Function successful
 *      - LE_BAD_PARAMETER  A parameter is incorrect
 *      - LE_FAULT          Function failed
 *      - LE_UNSUPPORTED    Function not supported by the target
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_GetTimeWithTimeProtocol
(
    const char* serverStrPtr,       ///< [IN]  Time server
    pa_dcs_TimeStruct_t* timePtr    ///< [OUT] Time structure
)
{
    le_result_t result = LE_FAULT;
    FILE* fp;
    char systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};
    char output[MAX_SYSTEM_CMD_OUTPUT_LENGTH];
    struct tm tm = {0};

    if ((!serverStrPtr) || ('\0' == serverStrPtr[0]) || (!timePtr))
    {
        LE_ERROR("Incorrect parameter");
        return LE_BAD_PARAMETER;
    }

    // Use rdate
    snprintf(systemCmd, sizeof(systemCmd), "/usr/sbin/rdate -p %s", serverStrPtr);
    fp = popen(systemCmd, "r");
    if (!fp)
    {
        LE_ERROR("Failed to run command '%s' (%m)", systemCmd);
        return LE_FAULT;
    }

    // Retrieve output
    while ((NULL != fgets(output, sizeof(output)-1, fp)) && (LE_OK != result))
    {
        if (NULL != strptime(output, "%a %b %d %H:%M:%S %Y", &tm))
        {
            timePtr->msec = 0;
            timePtr->sec  = tm.tm_sec;
            timePtr->min  = tm.tm_min;
            timePtr->hour = tm.tm_hour;
            timePtr->day  = tm.tm_mday;
            timePtr->mon  = 1 + tm.tm_mon; // Convert month range to [1..12]
            timePtr->year = 1900 + tm.tm_year;
            result = LE_OK;
        }
    }

    pclose(fp);
    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Retrieve time from a server using the Network Time Protocol.
 *
 * @return
 *      - LE_OK             Function successful
 *      - LE_BAD_PARAMETER  A parameter is incorrect
 *      - LE_FAULT          Function failed
 *      - LE_UNSUPPORTED    Function not supported by the target
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_GetTimeWithNetworkTimeProtocol
(
    const char* serverStrPtr,       ///< [IN]  Time server
    pa_dcs_TimeStruct_t* timePtr    ///< [OUT] Time structure
)
{
    if ((!serverStrPtr) || ('\0' == serverStrPtr[0]) || (!timePtr))
    {
        LE_ERROR("Incorrect parameter");
        return LE_BAD_PARAMETER;
    }

    // ntpdate is not supported yet
    return LE_UNSUPPORTED;
}


//--------------------------------------------------------------------------------------------------
/**
 * Query for a connection's network interface state
 *
 * @return
 *      - LE_OK             Function successful
 *      - LE_BAD_PARAMETER  A parameter is incorrect
 *      - LE_FAULT          Function failed
 *      - LE_UNSUPPORTED    Function not supported by the target
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_GetInterfaceState
(
    const char *interface,  ///< [IN] network interface name
    bool *stateIsUp         ///< [OUT] interface state down/up as false/true
)
{
    le_result_t result = LE_FAULT;
    FILE* fp;
    char systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};
    char output[MAX_SYSTEM_CMD_OUTPUT_LENGTH];

    *stateIsUp = false;
    snprintf(systemCmd, sizeof(systemCmd), "/sbin/ip address show dev %s", interface);
    fp = popen(systemCmd, "r");
    if (!fp)
    {
        LE_ERROR("Failed to run command '%s' (%m) to get interface state", systemCmd);
        return LE_FAULT;
    }

    // Retrieve output
    while (NULL != fgets(output, sizeof(output)-1, fp))
    {
        if (strstr(output, "inet"))
        {
            *stateIsUp = true;
            break;
        }
    }

    result = LE_OK;
    pclose(fp);
    LE_DEBUG("Interface %s in state %s", interface, (*stateIsUp) ? "up" : "down");
    return result;
}


//--------------------------------------------------------------------------------------------------
/**
 * Component init
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
}
