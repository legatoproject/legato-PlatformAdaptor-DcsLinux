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
#define IPV4_ROUTE_FILE "/proc/net/route"
#define IPV6_ROUTE_FILE "/proc/net/ipv6_route"

//--------------------------------------------------------------------------------------------------
/**
 * The linux system file $PLATFORM_ENVIRONMENT_VARIABLE_FILE with the environment settings
 * necessary to set before running udhcpc on Linux, as well as the environment variable
 * $UDHCPC_DEFAULT_ROUTE_VARIABLE_NAME that contains the udhcpc file name for use with udhcpc
 * that determines to always set a default route on the interface where udhcpc completes running
 * or not, i.e. skip such default route setting if this $$UDHCPC_DEFAULT_ROUTE_VARIABLE_NAME file
 * is present.
 * UDHCPC_OPTION_FILE_NAME_MAX_LENGTH is the max length of the name of a udhcpc option file, e.g.
 * /tmp/udhcpc_keep_default_route & /tmp/udhcpc_keep_default_resolv which lenghts are in the 30s.
 */
//--------------------------------------------------------------------------------------------------
#define PLATFORM_ENVIRONMENT_VARIABLE_FILE "/etc/run.env"
#define UDHCPC_DEFAULT_ROUTE_VARIABLE_NAME "UDHCPC_KEEP_DEFAULT_ROUTE"
#define UDHCPC_DEFAULT_RESOLV_VARIABLE_NAME "UDHCPC_KEEP_DEFAULT_RESOLV"
#define UDHCPC_OPTION_FILE_NAME_MAX_LENGTH 50

//--------------------------------------------------------------------------------------------------
/**
 * The linux system file to read for default gateway
 */
//--------------------------------------------------------------------------------------------------
#define DHCP_LEASE_FILE_PATH "/var/run/udhcpc.%s.leases"

//--------------------------------------------------------------------------------------------------
/**
 * Command to retrieve PID of DHCP running specific network interface
 */
//--------------------------------------------------------------------------------------------------
#define COMMAND_GET_DHCP_PID "/bin/ps -ax | grep dhcp | grep %s"

//--------------------------------------------------------------------------------------------------
/**
 * Command to terminate process with specific PID
 */
//--------------------------------------------------------------------------------------------------
#define COMMAND_TERMINATE_PID "/bin/kill %s"

//--------------------------------------------------------------------------------------------------
/**
 * Command to kill process with specific PID
 */
//--------------------------------------------------------------------------------------------------
#define COMMAND_KILL_PID "/bin/kill -9 %s"

//--------------------------------------------------------------------------------------------------
/**
 * Retry times
 */
//--------------------------------------------------------------------------------------------------
#define RETRY   3

//--------------------------------------------------------------------------------------------------
/**
 * Path to the 'ip' tool.
 */
//--------------------------------------------------------------------------------------------------
#define IP_TOOL "/sbin/ip"

//--------------------------------------------------------------------------------------------------
/**
 * Buffer to store resolv.conf cache
 */
//--------------------------------------------------------------------------------------------------
static char ResolvConfBuffer[256];

//--------------------------------------------------------------------------------------------------
/**
 * Typedef of the function vectors for parsing the default GW address setting on the system which
 * includes the GW address and the interface/device on which it is set. This is for use by both
 * IPv4 and IPv6. The result of the config parsing is saved in the last output argument.
 */
//--------------------------------------------------------------------------------------------------
typedef bool (*DefaultGwParserFunc_t)
(
    char* line,                  ///< [IN] line of system config to be parsed
    char* defaultGW,             ///< [OUT] string buffer for the GW address retrieved
    size_t defaultGWSize,        ///< [IN] size of the buffer provided above
    char* defaultInterface,      ///< [OUT] string buffer for the interface/device retrieved
    size_t defaultInterfaceSize, ///< [IN] size of the buffer provided above
    le_result_t* result          ///< [OUT] output of the config parsing
);

//--------------------------------------------------------------------------------------------------
/**
 * Function prototype
 */
//--------------------------------------------------------------------------------------------------
static le_result_t IsDefaultGatewayPresent(bool *v4Present, bool *v6Present);


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
 *      LE_OK           Function succeed
 *      LE_DUPLICATE    Function found no need to add as the given inputs are already set in
 *      LE_UNSUPPORTED  Function not supported by the target
 *      LE_FAULT        Function failed
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
                    LE_INFO("DNS 1 '%s' found in file", dns1Ptr);
                    addDns1 = false;
                }
                else if (NULL != strstr(currentLinePtr, dns2Ptr))
                {
                    LE_INFO("DNS 2 '%s' found in file", dns2Ptr);
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
        LE_DEBUG("No need to change the file");
        return LE_DUPLICATE;
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
 * Returns DHCP lease file path
 *
 * @return
 *      LE_OVERFLOW     Destination buffer too small and output will be truncated
 *      LE_UNSUPPORTED  If not supported by OS
 *      LE_FAULT        Function has failed
 *      LE_OK           Function has succeed
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_dcs_GetDhcpLeaseFilePath
(
    const char*  interfaceStrPtr,   ///< [IN] Pointer on the interface name
    char*        pathPtr,           ///< [OUT] Output 1 pointer
    size_t       bufferSize         ///< [IN]  Size of buffer
)
{
    int retVal = snprintf(pathPtr,
                          bufferSize,
                          DHCP_LEASE_FILE_PATH,
                          interfaceStrPtr
                         );

    if (retVal < 0)
    {
        *pathPtr = '\0';
        LE_ERROR("Failed writing lease file path");
        return LE_FAULT;
    }
    else if (retVal >= bufferSize)
    {
        LE_ERROR("Lease file path was truncated");
        return LE_OVERFLOW;
    }
    else
    {
        return LE_OK;
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the DNS configuration
 *
 * @return
 *      LE_OK           Function succeed
 *      LE_DUPLICATE    Function found no need to add as the given inputs are already set in
 *      LE_UNSUPPORTED  Function not supported by the target
 *      LE_FAULT        Function failed
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
 * Create a system file for use with DHCP with the provided name that is given in an absoulte path
 *
 * @return
 *      true   A system file is created with the given file name
 *      false  Otherwise, due to input error or access permission
 */
//--------------------------------------------------------------------------------------------------
static bool CreateDhcpSystemFile
(
    char* fileName
)
{
    FILE* filePtr;
    mode_t oldMask;
    bool ret = true;

    // Allow fopen to create file with mode=644
    oldMask = umask(022);

    // Open & write into the file to force its creation, which is similar to touching the file but
    // safer than running system command "touch <fileName>" in case fileName might include from
    // hackers other dangerous commands behind "&&", ";", etc., e.g. fileName =
    // "/tmp/udhcpc_keep_default_route && rm -rf /legato". Such inputs can't pass fopen(fileName).
    filePtr = fopen(fileName, "w");
    if (!filePtr)
    {
        LE_ERROR("Invalid name %s to create & open a file with", fileName);
        umask(oldMask);
        return false;
    }
    if (fprintf(filePtr, "%c", EOF) < 0)
    {
        LE_ERROR("Failed to write into file %s", fileName);
        ret = false;
    }

    umask(oldMask);
    if (0 != fclose(filePtr))
    {
        LE_WARN("fclose failed");
        ret = false;
    }

    return ret;
}

//--------------------------------------------------------------------------------------------------
/**
 * Validate the given file name and strip off any EOF or line feed at its end when found valid
 *
 * @return
 *      true   The given system file name is valid
 *      false  Otherwise
 */
//--------------------------------------------------------------------------------------------------
static bool ValidateFileName
(
    char* fileName
)
{
    uint16_t length;
    if (!fileName || ((length = strlen(fileName)) <= 0))
    {
        LE_ERROR("Invalid file name being blank");
        return false;
    }
    if (fileName[0] != '/')
    {
        LE_ERROR("Invalid system file name not in an absolute path");
        return false;
    }
    if (strstr(fileName, "../"))
    {
        LE_ERROR("Invalid system file name with ../ included");
        return false;
    }

    // Strip off any EOF or line feed character at the end of the file name
    if ((fileName[length-1] == EOF) || (fileName[length-1] == '\n'))
    {
        fileName[length-1] = '\0';
    }
    return true;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set up a udhcpc environment variable/file before running it. The resulting setting will be used
 * by its script in /etc/udhcpc.d/50default
 *
 * @return
 *      LE_FAULT        Function failed
 *      LE_OK           Function succeed
 */
//--------------------------------------------------------------------------------------------------
static le_result_t SetDhcpcEnvironment
(
    const char *variable
)
{
    le_result_t result = LE_OK;
    char udhcpFileName[UDHCPC_OPTION_FILE_NAME_MAX_LENGTH], systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};
    if (!variable)
    {
        LE_ERROR("Bad parameter!");
        return LE_FAULT;
    }
    snprintf(systemCmd, sizeof(systemCmd), "source %s; echo $%s",
             PLATFORM_ENVIRONMENT_VARIABLE_FILE, variable);
    FILE *fp = popen(systemCmd, "r");
    if (!fp)
    {
        LE_WARN("Failed to read environment variables in system file %s",
                PLATFORM_ENVIRONMENT_VARIABLE_FILE);
        return LE_OK;
    }
    else if (!fgets(udhcpFileName, sizeof(udhcpFileName), fp))
    {
        // This is a valid than an error case
        LE_DEBUG("No environment variable $%s set for udhcpc option file", variable);
    }
    else if (!ValidateFileName(udhcpFileName))
    {
        LE_ERROR("Invalid udhcpc option file name in $%s", variable);
        result = LE_FAULT;
    }
    else
    {
        // The name of the system file for specifying udhcpc's default option is defined. Thus,
        // create the file with this name to opt out of the default behavior
        if (!CreateDhcpSystemFile(udhcpFileName))
        {
            LE_ERROR("Failed to set option file with name %s from %s", udhcpFileName,
                     PLATFORM_ENVIRONMENT_VARIABLE_FILE);
            result = LE_FAULT;
        }
        else
        {
            LE_DEBUG("File %s set to skip changing the default behavior after udhcpc negotiation",
                     udhcpFileName);
        }
    }
    pclose(fp);
    return result;
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
    le_result_t result;
    int16_t systemResult;
    char systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};

    // Set up the udhcpc environment to skip the auto-installation of a default route onto the
    // interface with the default GW address given through the succeeded DHCP negotiation
    result = SetDhcpcEnvironment(UDHCPC_DEFAULT_ROUTE_VARIABLE_NAME);
    if (LE_OK != result)
    {
        return result;
    }

    // Set up the udhcpc environment to skip the auto-insertion of the DNS server addresses
    // given through the succeeded DHCP negotiation into the system's /etc/resolv.conf file
    result = SetDhcpcEnvironment(UDHCPC_DEFAULT_RESOLV_VARIABLE_NAME);
    if (LE_OK != result)
    {
        return result;
    }

    // DHCP Client
    snprintf(systemCmd, sizeof(systemCmd), "PATH=/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin;"
             "/sbin/udhcpc -R -b -i %s 2>&1", interfaceStrPtr);
    systemResult = system(systemCmd);
    if ((!WIFEXITED(systemResult)) || (0 != WEXITSTATUS(systemResult)))
    {
        LE_ERROR("DHCP client failed: command %s, result %d", systemCmd, systemResult);
        return LE_FAULT;
    }

    LE_INFO("DHCP client successful!");
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Stop DHCP running specific network interface
 *
 * @return
 *      - LE_OK             Function successful
 *      - LE_BAD_PARAMETER  Invalid parameter
 *      - LE_FAULT          Function failed
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_dcs_StopDhcp
(
    const char *interface   ///< [IN] Network interface name
)
{
    FILE*   fp;
    char*   pid;
    int     systemResult;
    char*   outputReentrant;
    char    systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};
    char    output[MAX_SYSTEM_CMD_OUTPUT_LENGTH] = {0};
    int     retry = 0;
    le_result_t result = LE_OK;

    if (NULL == interface)
    {
        LE_ERROR("Invalid parameter");
        return LE_BAD_PARAMETER;
    }

    snprintf(systemCmd, sizeof(systemCmd), COMMAND_GET_DHCP_PID, interface);
    fp = popen(systemCmd, "r");
    if(!fp)
    {
        LE_ERROR("Failed to run command '%s' (%m) to get interface state", systemCmd);
        return LE_FAULT;
    }

    while (NULL != fgets(output, sizeof(output)-1, fp))
    {
        // Retrieve PID of DHCP running specific interface
        outputReentrant = output;
        pid = strtok_r(outputReentrant, " ", &outputReentrant);
        if (NULL == pid)
        {
            LE_DEBUG("Failed to retrieve PID of DHCP running interface %s", interface);
        }
        else
        {
            //Kill the retrieved PID
            snprintf(systemCmd, sizeof(systemCmd), COMMAND_TERMINATE_PID, pid);
            systemResult = system(systemCmd);
            while (((!WIFEXITED(systemResult)) || (0 != WEXITSTATUS(systemResult)))
                   && (retry <= RETRY))
            {
                retry++;
                sleep(1 << retry);
                systemResult = system(systemCmd);
            }
            if (!WIFEXITED(systemResult) || (0 != WEXITSTATUS(systemResult)))
            {
                snprintf(systemCmd, sizeof(systemCmd), COMMAND_KILL_PID, pid);
                systemResult = system(systemCmd);
                if (!WIFEXITED(systemResult) || (0 != WEXITSTATUS(systemResult)))
                {
                    LE_WARN("system '%s' failed", systemCmd);
                    result = LE_FAULT;
                }
            }
        }
    }
    pclose(fp);
    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Validate IPv4/v6 address format
 *
 * @return
 *      - LE_OK     on success
 *      - LE_FAULT  on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t pa_dcs_ValidateIpAddress
(
    int af,             ///< Address family
    const char* addStr  ///< IP address to check
)
{
    struct sockaddr_in6 sa;

    if (inet_pton(af, addStr, &(sa.sin6_addr)))
    {
        return LE_OK;
    }
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Executes change route. It adds or removes a route, according to the input action flag, in the
 * first argument for the given destination address and subnet prefix length
 * onto the given network interface in the last argument.
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
    const char*            prefixLengthPtr,
    const char*            interfaceStrPtr
)
{
    char *actionStr, systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};
    int ipVersion = 4;
    int16_t systemResult;

    if (LE_OK == pa_dcs_ValidateIpAddress(AF_INET6, ipDestAddrStrPtr))
    {
        ipVersion = 6;
    }
    else if (LE_OK == pa_dcs_ValidateIpAddress(AF_INET, ipDestAddrStrPtr))
    {
        ipVersion = 4;
    }
    else
    {
        LE_ERROR("Invalid IP address format in %s", ipDestAddrStrPtr);
        return LE_FAULT;
    }

    switch (routeAction)
    {
        case PA_DCS_ROUTE_ADD:
            actionStr = "add";
            break;

        case PA_DCS_ROUTE_DELETE:
            actionStr = "del";
            break;

        default:
            LE_ERROR("Unknown action %d", (uint16_t)routeAction);
            return LE_FAULT;
    }

    // The command line to be formulated below will look like the following:
    // When prefixLengthPtr is not a null string, it's a network route change.
    // The command to run for IPv4 becomes:
    //     /sbin/ip -4 route add <addr>/<prefixLength> dev <interface>
    // for IPv6 becomes:
    //     /sbin/ip -6 route add <addr>/<prefixLength> dev <interface>
    //
    // When prefixLengthPtr is a null string, it's a host route change.
    // The command to run for IPv4 becomes:
    //     /sbin/ip -4 route add <addr> dev <interface>
    // for IPv6 becomes:
    //     /sbin/ip -6 route add <addr> dev <interface>
    //
    if (prefixLengthPtr && (strlen(prefixLengthPtr) > 0))
    {
        // Adding a network route
        if (snprintf(systemCmd, sizeof(systemCmd), IP_TOOL " -%d route %s %s/%s dev %s",
                     ipVersion, actionStr, ipDestAddrStrPtr, prefixLengthPtr, interfaceStrPtr)
            >= sizeof(systemCmd))
        {
            goto truncated;
        }
    }
    else
    {
        // Adding a host route
        if (snprintf(systemCmd, sizeof(systemCmd), IP_TOOL " -%d route %s %s dev %s",
                     ipVersion, actionStr, ipDestAddrStrPtr, interfaceStrPtr)
            >= sizeof(systemCmd))
        {
            goto truncated;
        }
    }

    LE_DEBUG("Execute '%s'", systemCmd);
    systemResult = system(systemCmd);
    if ((!WIFEXITED(systemResult)) || (0 != WEXITSTATUS(systemResult)))
    {
        LE_WARN("system '%s' failed; execution result: %d", systemCmd, systemResult);
        return LE_FAULT;
    }

    return LE_OK;

truncated:
    LE_DEBUG("Truncated system command '%s' not executed.", systemCmd);
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Delete the default gateway address(es) from the system as indicated by the IPv4/v6 booleans,
 * and save the corresponding results in the output arguments.
 * If the caller doesn't select an IP version for default GW deletion, this function won't set its
 * output result code even when provided.
 */
//--------------------------------------------------------------------------------------------------
static void pa_dcs_DeleteDefaultGateway
(
    bool deleteV4Gw,             ///< [IN] To delete default IPv4 GW or not
    bool deleteV6Gw,             ///< [IN] To delete default IPv6 GW or not
    le_result_t* resultV4,       ///< [OUT] Result of default IPv4 GW deletion
    le_result_t* resultV6        ///< [OUT] Result of default IPv6 GW deletion
)
{
    char systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};
    bool v4GwPresent, v6GwPresent;
    int systemResult;

    // Initiate the result code only if the caller cares about that IP version
    if (deleteV4Gw && resultV4)
    {
        *resultV4 = LE_FAULT;
    }
    if (deleteV6Gw && resultV6)
    {
        *resultV6 = LE_FAULT;
    }

    if ((deleteV4Gw && !resultV4) || (deleteV6Gw && !resultV6))
    {
        LE_ERROR("Error in input argument being null");
        return;
    }

    if (IsDefaultGatewayPresent(&v4GwPresent, &v6GwPresent) != LE_OK)
    {
        LE_ERROR("Failed to retrieve present default GW setting");
        return;
    }

    if (deleteV4Gw)
    {
        *resultV4 = LE_OK;
        if (v4GwPresent)
        {
            // Remove the current default IPv4 GW addr from the system
            snprintf(systemCmd, sizeof(systemCmd), IP_TOOL " -4 route del default");
            LE_DEBUG("Execute '%s'", systemCmd);
            systemResult = system(systemCmd);
            if ((!WIFEXITED(systemResult)) || (0 != WEXITSTATUS(systemResult)))
            {
                LE_WARN("system '%s' failed", systemCmd);
                *resultV4 = LE_FAULT;
            }
        }
    }

    if (deleteV6Gw)
    {
        *resultV6 = LE_OK;
        if (v6GwPresent)
        {
            // Remove the current default IPv6 GW addr from the system
            snprintf(systemCmd, sizeof(systemCmd), IP_TOOL " -6 route del default");
            LE_DEBUG("Execute '%s'", systemCmd);
            systemResult = system(systemCmd);
            if ((!WIFEXITED(systemResult)) || (0 != WEXITSTATUS(systemResult)))
            {
                LE_WARN("system '%s' failed", systemCmd);
                *resultV6 = LE_FAULT;
            }
        }
    }
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
    int         systemResult, ipVersion = isIpv6 ? 6 : 4;
    char        systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};
    le_result_t v4Result, v6Result;

    pa_dcs_DeleteDefaultGateway(!isIpv6, isIpv6, &v4Result, &v6Result);
    if ((isIpv6 && (v6Result != LE_OK)) || (!isIpv6 && (v4Result != LE_OK)))
    {
        LE_DEBUG("No successful deletion of current default IPv%1d GW address from system",
                 ipVersion);
    }

    if ((0 == strcmp(gatewayPtr, "")) || (0 == strcmp(interfacePtr, "")))
    {
        LE_DEBUG("Skip setting default IPv%1d GW config with either GW addr or interface empty",
                 ipVersion);
        return LE_OK;
    }

    LE_DEBUG("Installing default IPv%1d GW '%s' on '%s'", ipVersion, gatewayPtr, interfacePtr);

    // TODO: use of ioctl instead, should be done when rework the DCS
    snprintf(systemCmd, sizeof(systemCmd), IP_TOOL " -%d route add default via %s dev %s",
             ipVersion, gatewayPtr, interfacePtr);
    LE_DEBUG("Execute '%s'", systemCmd);
    systemResult = system(systemCmd);
    if ((!WIFEXITED(systemResult)) || (0 != WEXITSTATUS(systemResult)))
    {
        LE_WARN("system '%s' failed", systemCmd);
        return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Compress a given fully expanded IPv6 address in string format without no : separator, as the
 * IPv6 addresses shown in the IPv6 route table in /proc/net/ipv6_route to eliminate consecutive
 * 0s and add back the : separator accordingly
 *
 * @return
 *      true:  Compression of the given IPv6 address has been successfully completed
 *      false: Otherwise, due to input error
 */
//--------------------------------------------------------------------------------------------------
static bool CompressIPv6String
(
    char *ipv6String,
    size_t stringLen,
    char* compressedString
)
{
    struct in6_addr sin6_addr;
    char str[INET6_ADDRSTRLEN] = {0};
    uint16_t i;

    if ((stringLen != (4 * 8)) && (strstr(ipv6String, ":") != NULL))
    {
        // Don't compress as the given ipv6String isn't in the expected format
        return false;
    }

    // Add the : separator back before compressing consecutive 0s as shown in ipv6_route, e.g.
    // 200105696fff1766611fe749f326f0e2 to get 2001:0569:6fff:1766:611f:e749:f326:f0e2
    for (i=0; i<8; i++)
    {
        strncpy(&str[i * 5], &ipv6String[i * 4], 4);
        str[i * 5 + 4] = ':';
    }
    str[i * 5 - 1] = '\0';

    // Compress consecutive 0s via inet_ntop(AF_INETE6,...)
    inet_pton(AF_INET6, str, &sin6_addr);
    inet_ntop(AF_INET6, &sin6_addr, compressedString, INET6_ADDRSTRLEN);
    LE_DEBUG("IPv6 addr %s compressed to %s", ipv6String, compressedString);
    return true;
}

//--------------------------------------------------------------------------------------------------
/**
 * This is the IPv6 parser function of type DefaultGwParserFunc_t for parsing an output line with
 * the IPv6 default GW address or route setting on the system and extracting out the GW address and
 * the interface/device on which it is set to return back to the caller.
 *
 * @return
 *      true:  Info retrieval from the line is done and the caller can quit parsing further lines
 *      false: Retrieval of wanted info isn't done on this given line that the caller needs to
 *             continue parsing further lines for the necessary info
 */
//--------------------------------------------------------------------------------------------------
static bool IPv6DefaultGwParseLine
(
    char* line,
    char* defaultGW,
    size_t defaultGWSize,
    char* defaultInterface,
    size_t defaultInterfaceSize,
    le_result_t* result
)
{
    char *destAddr, *destPrefix, *sourceAddr, *sourcePrefix, *nextHop;
    char *metric, *refCount, *useCount, *flags, *device, *savePtr;
    char *blankAddr = "00000000000000000000000000000000";
    char *blankPrefix = "00";

    if ((defaultGWSize < INET6_ADDRSTRLEN))
    {
        *result = LE_OVERFLOW;
        return false;
    }

    // The following block extracts info from the given line displayed in the following format
    // and the order destAddr, destPrefix, sourceAddr, sourcePrefix, nextHop, etc.:
    //     00000000000000000000000000000000 00 00000000000000000000000000000000 00
    //         200105696ff8e36fc5b4e5786e0fdf6d 00000400 00000000 00000000 00000003 rmnet_data0
    destAddr     = strtok_r(line, " \t", &savePtr);
    destPrefix   = strtok_r(NULL, " \t", &savePtr);
    sourceAddr   = strtok_r(NULL, " \t", &savePtr);
    sourcePrefix = strtok_r(NULL, " \t", &savePtr);
    nextHop      = strtok_r(NULL, " \t", &savePtr);
    metric       = strtok_r(NULL, " \t", &savePtr);
    refCount     = strtok_r(NULL, " \t", &savePtr);
    useCount     = strtok_r(NULL, " \t", &savePtr);
    flags        = strtok_r(NULL, " \t", &savePtr);
    device       = strtok_r(NULL, " \t", &savePtr);

    if (!destAddr || !destPrefix || !sourceAddr || !sourcePrefix || !nextHop || !device)
    {
        *result = LE_NOT_FOUND;
        return false;
    }

    if ((0 == strcmp(destAddr , blankAddr)) && (0 == strcmp(destPrefix , blankPrefix)) &&
        (0 == strcmp(sourceAddr , blankAddr)) && (0 == strcmp(sourcePrefix , blankPrefix)) &&
        (0 != strcmp(nextHop, blankAddr)) && (strlen(device) > 0))
    {
        // The default GW's entry in the IPv6 route table is denoted by zero destination address
        // and prefix, zero source address and prefix, and a non-zero next hop with a non-blank
        // device/interface
        LE_DEBUG("Default IPv6 GW found: address %s, interface %s", nextHop, device);
        LE_DEBUG("With metric %s, refCount %s, useCount %s, flags %s", metric, refCount,
                 useCount, flags);

        if (!CompressIPv6String(nextHop, strlen(nextHop), defaultGW))
        {
            LE_WARN("Parsed IPv6 address %s not in expected format", nextHop);
            *result = LE_FAULT;
            return false;
        }

        *result = le_utf8_Copy(defaultInterface, device, defaultInterfaceSize, NULL);
        if (*result != LE_OK)
        {
            LE_WARN("interface buffer too small to save the retrieved");
        }

        // Return true to let the caller's loop stop parsing further lines
        return true;
    }

    *result = LE_NOT_FOUND;
    return false;
}

//--------------------------------------------------------------------------------------------------
/**
 * This is the IPv4 parser function of type DefaultGwParserFunc_t for parsing an output line with
 * the IPv6 default GW address or route setting on the system and extracting out the GW address and
 * the interface/device on which it is set to return back to the caller.
 *
 * @return
 *      true:  Info retrieval from the line is done and the caller can quit parsing further lines
 *      false: Retrieval of wanted info isn't done on this given line that the caller needs to
 *             continue parsing further lines for the necessary info
 */
//--------------------------------------------------------------------------------------------------
static bool IPv4DefaultGwParseLine
(
    char* line,
    char* defaultGW,
    size_t defaultGWSize,
    char* defaultInterface,
    size_t defaultInterfaceSize,
    le_result_t* result
)
{
    char *ifacePtr, *destPtr, *gwPtr, *savePtr, *pEnd;
    struct in_addr addr;

    // The following block extracts info from the given line displayed in the following format
    // and the order ifacePtr, destPtr, gwPtr, etc.:
    //     ecm0 0002A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0
    ifacePtr = strtok_r(line, " \t", &savePtr);
    destPtr  = strtok_r(NULL, " \t", &savePtr);
    gwPtr    = strtok_r(NULL, " \t", &savePtr);

    if (!ifacePtr || !destPtr || (0 != strcmp(destPtr , "00000000")))
    {
        // Return false to let the caller's loop continue parsing the next line
        *result = LE_NOT_FOUND;
        return false;
    }

    if (!gwPtr)
    {
        *result = LE_NOT_FOUND;
        return false;
    }

    addr.s_addr = (uint32_t)strtoul(gwPtr, &pEnd, 0x10);;
    *result = le_utf8_Copy(defaultInterface, ifacePtr, defaultInterfaceSize, NULL);
    if (*result != LE_OK)
    {
        LE_WARN("interface buffer too small to save the retrieved");
        return false;
    }

    *result = le_utf8_Copy(defaultGW, inet_ntoa(addr), defaultGWSize, NULL);
    if (*result != LE_OK)
    {
        LE_WARN("gateway buffer too small to save the retrieved");
    }

    // Return true to let the caller's loop stop parsing further lines
    return true;
}

//--------------------------------------------------------------------------------------------------
/**
 * Retrieve the default route/GW address and the interface on which it is set from the route info
 * file given in the 1st input argument. This function supports both IPv4 & IPv6 and which one it
 * is depends on the given routeInfoFile; if it is IPv4, this input is IPV4_ROUTE_FILE; if IPv6,
 * it is IPV6_ROUTE_FILE.
 *
 * @return
 *     - LE_OK if the retrieval of default GW address(es) has been successful
 *     - LE_NOT_FOUND if no currently set default GW address has been found
 *     - LE_FAULT if the attempt to retrieve has failed
 *     - LE_OVERFLOW if the address retrieved exceeds the provided buffer's length
 */
//--------------------------------------------------------------------------------------------------
static le_result_t pa_dcs_ParseDefaultGatewaySetting
(
    char* routeInfoFile,
    DefaultGwParserFunc_t parserFunc,
    char* defaultGW,
    size_t defaultGWSize,
    char* defaultInterface,
    size_t defaultInterfaceSize
)
{
    le_result_t result;
    FILE*       routeFile;
    char        line[200];

    routeFile = le_flock_OpenStream(routeInfoFile, LE_FLOCK_READ, &result);
    if (NULL == routeFile)
    {
        LE_ERROR("Could not open file %s", routeInfoFile);
        return LE_FAULT;
    }

    result = LE_NOT_FOUND;

    while (fgets(line, sizeof(line), routeFile))
    {
        if (parserFunc(line, defaultGW, defaultGWSize, defaultInterface, defaultInterfaceSize,
                       &result))
        {
            break;
        }
    }
    le_flock_CloseStream(routeFile);

    switch (result)
    {
        case LE_OK:
            LE_DEBUG("default GW retrieved from %s: '%s' on '%s'", routeInfoFile,
                     defaultGW, defaultInterface);
            break;

        case LE_NOT_FOUND:
            LE_DEBUG("No default GW to retrieve from %s", routeInfoFile);
            break;

        default:
            LE_WARN("Could not retrieve default GW from %s", routeInfoFile);
            break;
    }
    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Save the current default route or GW address setting on the system into the input data structure
 * provided, as well as the interface on which it is set, including both IPv4 and IPv6
 */
//--------------------------------------------------------------------------------------------------
void pa_dcs_GetDefaultGateway
(
    pa_dcs_DefaultGwBackup_t* defGwConfigBackupPtr,
    le_result_t* v4Result,
    le_result_t* v6Result
    )
{
    if (!defGwConfigBackupPtr || !v4Result || !v6Result)
    {
        LE_ERROR("Input errors with null");
        if (v4Result)
        {
            *v4Result = LE_FAULT;
        }
        if (v6Result)
        {
            *v6Result = LE_FAULT;
        }
        return;
    }

    *v6Result = pa_dcs_ParseDefaultGatewaySetting(
        IPV6_ROUTE_FILE, IPv6DefaultGwParseLine,
        defGwConfigBackupPtr->defaultV6GW, sizeof(defGwConfigBackupPtr->defaultV6GW),
        defGwConfigBackupPtr->defaultV6Interface, sizeof(defGwConfigBackupPtr->defaultV6Interface));

    *v4Result = pa_dcs_ParseDefaultGatewaySetting(
        IPV4_ROUTE_FILE, IPv4DefaultGwParseLine,
        defGwConfigBackupPtr->defaultV4GW, sizeof(defGwConfigBackupPtr->defaultV4GW),
        defGwConfigBackupPtr->defaultV4Interface, sizeof(defGwConfigBackupPtr->defaultV4Interface));

}

//--------------------------------------------------------------------------------------------------
/**
 * Check if IPv4 and IPv6 default route or GW address is set.
 *
 * @return
 *     - LE_OK if the retrieval of a default GW address has been successful
 *     - LE_FAULT if the attempt to retrieve any has failed
 */
//--------------------------------------------------------------------------------------------------
static le_result_t IsDefaultGatewayPresent
(
    bool *v4Present,
    bool *v6Present
)
{
    le_result_t v4ret, v6ret;
    pa_dcs_DefaultGwBackup_t backup;
    if (!v4Present || !v6Present)
    {
        return LE_FAULT;
    }

    memset(&backup, 0x0, sizeof(pa_dcs_DefaultGwBackup_t));
    pa_dcs_GetDefaultGateway(&backup, &v4ret, &v6ret);
    *v4Present = ((v4ret == LE_OK) && (strlen(backup.defaultV4GW) > 0));
    *v6Present = ((v6ret == LE_OK) && (strlen(backup.defaultV6GW) > 0));
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Used the data backup upon connection to remove DNS entries locally added
 */
//--------------------------------------------------------------------------------------------------
void pa_dcs_RestoreInitialDnsNameServers
(
    pa_dcs_DnsBackup_t* dnsConfigBackupPtr
)
{
    if (   ('\0' != dnsConfigBackupPtr->newDnsIPv4[0][0])
        || ('\0' != dnsConfigBackupPtr->newDnsIPv4[1][0])
       )
    {
        LE_DEBUG("Removing IPv4 DNS server addresses %s & %s from device",
                 dnsConfigBackupPtr->newDnsIPv4[0],
                 dnsConfigBackupPtr->newDnsIPv4[1]);
        RemoveNameserversFromResolvConf(
                                 dnsConfigBackupPtr->newDnsIPv4[0],
                                 dnsConfigBackupPtr->newDnsIPv4[1]);

        // Delete backed up data
        memset(dnsConfigBackupPtr->newDnsIPv4[0], '\0',
               sizeof(dnsConfigBackupPtr->newDnsIPv4[0]));
        memset(dnsConfigBackupPtr->newDnsIPv4[1], '\0',
               sizeof(dnsConfigBackupPtr->newDnsIPv4[1]));
    }

    if (   ('\0' != dnsConfigBackupPtr->newDnsIPv6[0][0])
        || ('\0' != dnsConfigBackupPtr->newDnsIPv6[1][0])
       )
    {
        LE_DEBUG("Removing IPv6 DNS server addresses %s & %s from device",
                 dnsConfigBackupPtr->newDnsIPv6[0],
                 dnsConfigBackupPtr->newDnsIPv6[1]);
        RemoveNameserversFromResolvConf(
                                 dnsConfigBackupPtr->newDnsIPv6[0],
                                 dnsConfigBackupPtr->newDnsIPv6[1]);

        // Delete backed up data
        memset(dnsConfigBackupPtr->newDnsIPv6[0], '\0',
               sizeof(dnsConfigBackupPtr->newDnsIPv6[0]));
        memset(dnsConfigBackupPtr->newDnsIPv6[1], '\0',
               sizeof(dnsConfigBackupPtr->newDnsIPv6[1]));
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
    bool *ipv4IsUp,         ///< [INOUT] IPV4 is not assigned/assigned as false/true
    bool *ipv6IsUp          ///< [INOUT] IPV6 is not assigned/assigned as false/true
)
{
    le_result_t result = LE_FAULT;
    FILE* fp;
    char systemCmd[MAX_SYSTEM_CMD_LENGTH] = {0};
    char output[MAX_SYSTEM_CMD_OUTPUT_LENGTH];

    if ((!interface) || (!ipv4IsUp) || (!ipv6IsUp))
    {
        LE_ERROR("Invalid parameter");
        return LE_BAD_PARAMETER;
    }

    *ipv4IsUp = false;
    *ipv6IsUp = false;
    snprintf(systemCmd, sizeof(systemCmd), IP_TOOL " address show dev %s", interface);
    fp = popen(systemCmd, "r");
    if (!fp)
    {
        LE_ERROR("Failed to run command '%s' (%m) to get interface state", systemCmd);
        return LE_FAULT;
    }

    // Retrieve output
    while (NULL != fgets(output, sizeof(output)-1, fp))
    {
        if (strstr(output, "inet6"))
        {
            *ipv6IsUp = true;
        }
        else if (strstr(output, "inet"))
        {
            *ipv4IsUp = true;
        }
    }

    result = LE_OK;
    pclose(fp);
    LE_DEBUG("Interface %s in state: IPV4 %s, IPV6 %s", interface,
             (*ipv4IsUp) ? "up" : "down",
             (*ipv6IsUp) ? "up" : "down");
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
