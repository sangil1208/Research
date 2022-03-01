/**
 * @addtogroup mk2mac_test MK2 MLME_IF test application(s)
 * @{
 *
 * @file
 * test-tx: Transmit packets in one of two modes
 *          1/ Command line options
 *          2/ Listen on port and forward
 *
 *
 */

//------------------------------------------------------------------------------
// Copyright (c) 2010 Cohda Wireless Pty Ltd
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Included headers
//------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <assert.h>
#include <inttypes.h>

#include <sys/time.h> // for rate control
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <net/if.h>
//#include <arpa/inet.h>

#include "lib1609.h"
#include "test-common.h"
#include "TxOpts.h"
#include "test.h"

#define D_LOCAL D_WARN
#include "debug-levels.h"

//------------------------------------------------------------------------------
// Macros & Constants
//------------------------------------------------------------------------------

D_LEVEL_DECLARE();

// used to exit gracefully on ctrl-c
bool TxContinue = true;

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------

// TZSP Tag created by udptest (at 5 Oct 2010)
typedef struct TZSPHeader_tag
{
  uint8_t Version;
  uint8_t Type;
  uint16_t Encapsulates; // should be 0x0012
  uint8_t FirstTagID; // should be 0xf2
  uint8_t TagLength; // should be 0x0e
  uint32_t Magic; // should be 0xc0da0001
  uint8_t RateID; // e.g. 0x0a
} __attribute__ ((packed)) tTZSPHeader;

/// All the test's state. Configuration stored separately in a tTxOpts object.
typedef struct Tx
{
  /// MLME_IF API function return code
  tMK2Status Res;
  /// wave-raw or wave-mgmt file descriptor
  int Fd;
  /// wave-raw or wave-mgmt if_index
  int IfIdx;
  /// Enum version of interface name
  tInterfaceID InterfaceID;
  /// Socket address
  struct sockaddr_ll SocketAddress;
  /// Tx Buffer (rather than re-alloc each time)
  unsigned char * pBuf;
  /// Ethernet header (for preloading invariants)
  struct ethhdr EthHdr;
  /// 802.11 MAC header (for preloading invariants)
  struct IEEE80211MACHdr Dot11Hdr;
  /// Tx descriptor
  struct MK2TxDescriptor TxDesc;
  /// Packet Log File
  FILE * fp;
  /// Unique Identifier for each packet (Sequence Number)
  uint32_t SeqNum;

} tTx;

//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

// local prototypes
static void Tx_Exit (tTx *pTx);

/**
 * @brief Initialize the Tx application
 * @param pTx handle to Tx Object with pointer to MLME_IF Handle
 * @param pTxOpts pointer Configuration Object
 * Set default values in the application's variables (the 'pTx' handle)
 */
void Tx_Init (tTx *pTx, tTxOpts * pTxOpts)
{

  pTx->Res = ~MK2STATUS_SUCCESS;
  pTx->Fd = -1; // File description invalid
  pTx->IfIdx = -1;
  pTx->SeqNum = 0;
  pTx->fp = NULL;

  // Create an output Buffer (could have large persistent Buf in pTx for speed)
  pTx->pBuf = (unsigned char *) malloc(TEST_MAX_FRAMESIZE);
  if (pTx->pBuf == NULL)
  {
    printf("Fail: malloc() errno %d\n", errno);
    pTx->Res = errno;
    Tx_Exit(pTx);
  }

  // PreLoad the Ethernet Header (used in RAW frames)
  memcpy(pTx->EthHdr.h_source, pTxOpts->SrcAddr, ETH_ALEN); // SA

  // preload 802.11 header (used in MGMT frames)
  pTx->Dot11Hdr.FrameControl = CpuToLe16(TEST_DOT11_FRAMECTL);
  pTx->Dot11Hdr.DurationId = CpuToLe16(TEST_DOT11_DURATIONID);
  memcpy(pTx->Dot11Hdr.Address2, pTxOpts->SrcAddr, ETH_ALEN); // SA
  memset(pTx->Dot11Hdr.Address3, 0x33, ETH_ALEN); // BSSID
  pTx->Dot11Hdr.SeqControl = CpuToLe16(TEST_DOT11_SEQCTL); // Sequence control info

  // Get internal quick Interface type from string
  if (strcmp("wave-raw", pTxOpts->pInterfaceName) == 0)
    pTx->InterfaceID = INTERFACEID_WAVERAW;
  else if (strcmp("wave-mgmt", pTxOpts->pInterfaceName) == 0)
    pTx->InterfaceID = INTERFACEID_WAVEMGMT;
  else if (strcmp("wave-data", pTxOpts->pInterfaceName) == 0)
    pTx->InterfaceID = INTERFACEID_WAVEDATA;
  else
  {
    printf("Fail: no such Interface %s\n", pTxOpts->pInterfaceName);
    pTx->Res = errno;
    Tx_Exit(pTx);
  }

  // Open a handle for the packet log file
  if (pTxOpts->pPacketLogFileName[0] != 0)
  {
    pTx->fp = fopen(pTxOpts->pPacketLogFileName, "w");
    if (pTx->fp == NULL)
    {
      printf("Fail: fopen(%s) errno %d\n", pTxOpts->pPacketLogFileName, errno);
      pTx->Res = errno;
      Tx_Exit(pTx);
    }
    else
    {
      d_printf(D_INFO, pTx, "Opened %s for logging (Handle %p)\n",
               pTxOpts->pPacketLogFileName, pTx->fp);
    }
  }

}

/**
 * @brief De-initialize the Tx application
 * @param pTx handle to Tx Object with pointers Socket and MLME_IF
 * Cleanup the application's variables (the 'pTx' handle)
 */
static void Tx_Exit (tTx *pTx)
{

  if (pTx->Fd >= 0)
  {
    close(pTx->Fd);
    pTx->Fd = -1;
  }

  // free any allocated tx Buf
  if (pTx->pBuf != NULL)
  {
    free(pTx->pBuf);
    pTx->pBuf = NULL;
  }

  // Close any open packet log file
  if (pTx->fp != NULL)
  {
    d_printf(D_INFO, pTx, "Closing logging File Handle %p.\n", pTx->fp);
    fclose(pTx->fp);
    pTx->fp = NULL;
  }

  exit(pTx->Res);
}

/**
 * @brief Open a raw linux (AF_PACKET) socket to a specific network interface
 * @param pName The name of the network interface
 * @return the socket's "fd", negative values are errno values
 */
static int Tx_OpenSocket (const char *pName)
{
  int Res = -ENOSYS;
  struct sockaddr_ll SocketAddress = { 0, };
  int SocketFd;

  SocketFd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (SocketFd < 0)
  {
    printf("socket() failed errno %d '%s'\n", errno, strerror(errno));
    return -errno;
  }

  SocketAddress.sll_family = AF_PACKET;
  SocketAddress.sll_protocol = htons(ETH_P_ALL);
  SocketAddress.sll_ifindex = if_nametoindex(pName);
  d_printf(D_DEBUG, NULL, "pName '%s' sll_ifindex %d\n", pName,
           SocketAddress.sll_ifindex);

  Res = bind(SocketFd, (struct sockaddr *) &SocketAddress,
             sizeof(SocketAddress));
  if (Res < 0)
  {
    printf("bind() failed errno %d '%s'\n", errno, strerror(errno));
    close(SocketFd);
    return Res;
  }

  // Set non-blocking mode
  {
    int Flags;
    Flags = fcntl(SocketFd, F_GETFL, 0);
    if (Flags == -1)
    {
      printf("fcntl(F_GETFL) failed errno %d '%s'\n", errno, strerror(errno));
      close(SocketFd);
      return -errno;
    }

    Res = fcntl(SocketFd, F_SETFL, Flags | O_NONBLOCK);
    if (Res < 0)
    {
      printf("fcntl(F_SETFL, O_NONBLOCK) failed errno %d '%s'\n", errno, strerror(errno));
      close(SocketFd);
      return Res;
    }
  }

  return SocketFd;
}

/**
 * @brief Open a raw linux (AF_PACKET) socket to the interface
 * @param pTx pointer to Tx Object owning Socket handle ("fd")
 */
static void Tx_OpenInterface (tTx * pTx, char * pInterfaceName)
{
  pTx->Fd = Tx_OpenSocket(pInterfaceName);
  if (pTx->Fd < 0)
  {
    printf("Fail: open '%s'\n", pInterfaceName);
    Tx_Exit(pTx);
  }
  pTx->IfIdx = if_nametoindex(pInterfaceName);
}

/**
 * @brief Close the socket associated with the interface
 * @param pTx pointer to Tx Object owning Socket handle ("fd")
 */
static void Tx_CloseInterface (tTx * pTx)
{
  if (pTx->Fd >= 0)
  {
    close(pTx->Fd);
    pTx->Fd = -1;
  }
  else
  {
    printf("Fail: close interface\n");
    Tx_Exit(pTx);
  }
}

void dumpsocketopts (int s)
{
  socklen_t optlen;
  struct timeval t;

  d_printf(D_DEBUG, NULL, "Socket %d\n", s);
  getsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &t, &optlen);
  d_printf(D_DEBUG, NULL, "  SNDTIMEO %lu\n", t.tv_sec);
  getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &t, &optlen);
  d_printf(D_DEBUG, NULL, "  RCVTIMEO %lu\n", t.tv_sec);

}

/**
 * @brief Print an MK2TxDescriptor
 * @param pMK2TxDesc the Descriptor to display
 *
 * prints headings if NULL
 */
static void MK2TxDescriptor_fprintf (FILE * fp, tMK2TxDescriptor * pMK2TxDesc)
{

  if (pMK2TxDesc == NULL)
  {
    // write headings
    /// Indicate the channel number that frame was received on
    fprintf(fp, "%3s ", "ChN");
    /// Indicate the priority allocated to the received packet (by Tx)
    fprintf(fp, "%3s ", "Pri");
    /// Indicate the 802.11 service class used to transmit the packet
    fprintf(fp, "%3s ", "Srv");
    /// Indicate the data rate that was used
    fprintf(fp, "%2s ", "MC");
    /// Indicate the power to be used (may specify default or TPC)
    fprintf(fp, "%6s ", "P(dBm)");
    /// Indicate the antenna upon which packet should be transmitted
    fprintf(fp, "%2s ", "An");
    /// Indicate the expiry time (0 means never)
    fprintf(fp, "%21s ", "Expiry (s)");
  }
  else
  {
    uint64_t Expiry_Seconds, Expiry_uSeconds;

    /// Indicate the channel number that frame was received on
    fprintf(fp, "%03d ", pMK2TxDesc->ChannelNumber);
    /// Indicate the priority allocated to the received packet (by Tx)
    fprintf(fp, "%03d ", pMK2TxDesc->Priority);
    /// Indicate the 802.11 service class used to transmit the packet
    fprintf(fp, "%03d ", pMK2TxDesc->Service);
    /// Indicate the data rate that was used
    fprintf(fp, "%02d ", pMK2TxDesc->MCS);
    /// Indicate the power to be used (may specify default or TPC)
    fprintf(fp, "%6.1f ", pMK2TxDesc->TxPower.ManualPower * 0.5);
    /// Indicate the antenna upon which packet should be transmitted
    fprintf(fp, "%02d ", pMK2TxDesc->TxAntenna);
    /// Indicate the expiry time (0 means never)
    Expiry_Seconds = pMK2TxDesc->Expiry / 1000000;
    Expiry_uSeconds = pMK2TxDesc->Expiry % 1000000;
    fprintf(fp, "%014" PRIu64 ".", Expiry_Seconds);
    fprintf(fp, "%06" PRIu64 " ", Expiry_uSeconds);
  }
}

/**
 * @brief Write the info in packet Buffer to Packet log
 * @param fp File Pointer (open)
 * @param pBuf the Buffer containing the Frame to be logged
 * @param FrameLen the number of relevant Bytes in the Buffer
 * @param DumpPayload Should the entire payload be dumped to file
 * @param DumpHeadings dump headings in addition to data?
 * @return Error Code
 *
 * Buffer includes RxDescriptor, Ethernet header, Payload and FCS
 *
 */
tTxErrCode Tx_fprintf_waveraw (FILE * fp,
                               char * pBuf,
                               int FrameLen,
                               bool DumpPayload,
                               bool DumpHeadings)
{
  tTxErrCode ErrCode = TX_ERR_NONE;
  tMK2TxDescriptor * pTxDesc; // TxDesc (will be Unpacked)
  struct ethhdr *pEthHdr; // pointer into Buf at Eth Hdr
  unsigned char *pPayload; // pointer in Buf at Payload (contains SeqNum)
  int PayloadLen; // Payload Length in Bytes

  if (fp == NULL)
  {
    printf("Fail: Tx_WriteToLog NULL FILE pointer\n");
    ErrCode = TX_ERR_NULLFILEPOINTER;
    return ErrCode;
  }

  if (pBuf == NULL)
  {
    printf("Fail: Tx_WriteToLog NULL Buffer\n");
    ErrCode = TX_ERR_NULLBUFFER;
    return ErrCode;
  }

  // Irrespective of raw/mgmt, TxDesc is first in frame
  pTxDesc = (tMK2TxDescriptor *) ((unsigned char *) pBuf);

  //--------------------------------------------------------------------------
  // WAVE-RAW frame: | TxDesc | Eth Header | Protocol & Payload |
  pEthHdr = (struct ethhdr *) ((unsigned char *) pTxDesc
                               + sizeof(tMK2TxDescriptor));
  pPayload = (unsigned char *) ((unsigned char *) pEthHdr
                                + sizeof(struct ethhdr));

  // now that we have pointer to structs, dump to file line

  // every now an then write a comment with column labels
  if ((DumpHeadings) || (fp == stdout))
  {
    fprintf(fp, "%10s ", "#   SeqNum");
    MK2TxDescriptor_fprintf(fp, NULL);
    EthHdr_fprintf(fp, NULL);
    Payload_fprintf(fp, NULL, 0, 0); // last two args ingnored
    fprintf(fp, "\n"); // end this packet line
  }

  // SeqNum is first 4 Bytes of Payload
  fprintf(fp, "%010d ", ntohl(*((uint32_t *) pPayload)));

  // Tx Descriptor has its own dumper
  MK2TxDescriptor_fprintf(fp, pTxDesc);
  EthHdr_fprintf(fp, pEthHdr);

  // calc Payload Length
  PayloadLen = FrameLen - ((unsigned long) pPayload - (unsigned long) pBuf);

  Payload_fprintf(fp, pPayload, PayloadLen, DumpPayload);

  fprintf(fp, "\n"); // end this packet line

  return ErrCode;
}

/**
 * @brief Write the info in packet Buffer to Packet log
 * @param fp File Pointer (open)
 * @param pBuf the Buffer containing the Frame to be logged
 * @param FrameLen the number of relevant Bytes in the Buffer
 * @param DumpPayload Should the entire payload be dumped to file
 * @param DumpHeadings dump headings in addition to data?
 * @return Error Code
 *
 * Buffer includes RxDescriptor, Ethernet header, Payload and FCS
 *
 */
tTxErrCode Tx_fprintf_wavemgmt (FILE * fp,
                                char * pBuf,
                                int FrameLen,
                                bool DumpPayload,
                                bool DumpHeadings)
{
  tTxErrCode ErrCode = TX_ERR_NONE;
  tMK2TxDescriptor * pTxDesc; // TxDesc (will be Unpacked)
  struct IEEE80211MACHdr *pDot11Hdr;
  unsigned char *pPayload; // pointer in Buf at Payload (contains SeqNum)
  int PayloadLen; // Payload Length in Bytes

  if (fp == NULL)
  {
    printf("Fail: Tx_WriteToLog NULL FILE pointer\n");
    ErrCode = TX_ERR_NULLFILEPOINTER;
    return ErrCode;
  }

  if (pBuf == NULL)
  {
    printf("Fail: Tx_WriteToLog NULL Buffer\n");
    ErrCode = TX_ERR_NULLBUFFER;
    return ErrCode;
  }

  // Irrespective of raw/mgmt, TxDesc is first in frame
  pTxDesc = (tMK2TxDescriptor *) ((char *) pBuf);

  //--------------------------------------------------------------------------
  // WAVE-MGMT frame: | TxDesc | 802.11 Header | Protocol & Payload |
  pDot11Hdr = (struct IEEE80211MACHdr *) ((char *) pTxDesc
                                          + sizeof(tMK2TxDescriptor));
  pPayload = (unsigned char *) ((char *) pDot11Hdr
                                + sizeof(struct IEEE80211MACHdr));

  // now that we have pointer to structs, dump to file line

  // every now an then write a comment with column labels
  if ((DumpHeadings) || (fp == stdout))
  {
    fprintf(fp, "%10s ", "#   SeqNum");
    MK2TxDescriptor_fprintf(fp, NULL);
    Dot11Hdr_fprintf(fp, NULL);
    Payload_fprintf(fp, NULL, 0, 0); // last two args ingnored
    fprintf(fp, "\n"); // end this packet line

  }

  // SeqNum is first 4 Bytes of Payload
  fprintf(fp, "%010d ", ntohl(*((uint32_t *) pPayload)));

  // Next fields have own dumper
  MK2TxDescriptor_fprintf(fp, pTxDesc);
  Dot11Hdr_fprintf(fp, pDot11Hdr);

  // calc Payload Length
  PayloadLen = FrameLen - ((unsigned long) pPayload - (unsigned long) pBuf);

  Payload_fprintf(fp, pPayload, PayloadLen, DumpPayload);

  fprintf(fp, "\n"); // end this packet line

  return ErrCode;
}

tTxErrCode Tx_fprintf (FILE * fp,
                       char * pBuf,
                       int FrameLen,
                       tInterfaceID InterfaceID,
                       bool DumpPayload,
                       bool DumpHeadings)
{
  tTxErrCode ErrCode = TX_ERR_NONE;

  if (fp == NULL)
    return ErrCode;

  switch (InterfaceID)
  {
    case INTERFACEID_WAVERAW:
      ErrCode = Tx_fprintf_waveraw(fp, pBuf, FrameLen, DumpPayload,
                                   DumpHeadings);
      break;
    case INTERFACEID_WAVEMGMT:
      ErrCode = Tx_fprintf_wavemgmt(fp, pBuf, FrameLen, DumpPayload,
                                    DumpHeadings);
      break;
    default:
      ErrCode = TX_ERR_INVALIDINTERFACE;
      break;
  }

  return ErrCode;

}

/**
 * @brief Transmit frame(s) on the opened interface using the CCH or SCH config
 * @param pTx pointer to Tx Object owning Socket handle
 * @param pTxOpts the options used to config the channel for sending
 * @param Pause_us wait this long inline with tx Loop
 * @return the number of bytes sent (-1 is failure)
 *
 * Loops through several variables transmitting several packets in a single call.
 * Loops though
 *   - Packet Length
 *   - Tx Power
 *   - MCS
 *
 * Source Address already loaded into tTx object
 */
tTxErrCode Tx_Send (tTx * pTx, tTxOpts * pTxOpts, int Pause_us)
{
  tTxErrCode ErrCode = TX_ERR_NONE;

  int m, r, a; // loop vars
  int ThisFrameLen, ThisBytesSent; // Number of Bytes
  char *pBuf; // Buffer to store Frame
  struct MK2TxDescriptor *pTxDesc;
  struct ethhdr *pEthHdr;
  unsigned char *pPayload;
  bool DumpHeadings; // in Packet Log file and/or to screen
  struct IEEE80211MACHdr *pDot11Hdr;
  long TxPower;
  tRangeSpec * pTxPowerRangeSpec;
  long PayloadLen;
  tRangeSpec * pPayloadLenRangeSpec;
  tTxCHOpts * pTxCHOpts;

  d_fnstart(D_DEBUG, pTx, "(pTx %p, pTxOpts %p, Pause_us %d)\n", pTx, pTxOpts,
            Pause_us);
  d_assert(pTx != NULL);
  d_assert(pTxOpts != NULL);

  // Get existing handles from Tx Object
  pBuf = (char *) (pTx->pBuf);
  pTxCHOpts = &(pTxOpts->TxCHOpts);

  d_assert(pBuf != NULL);
  d_assert(pTxCHOpts != NULL);

  // Irrespective of raw/mgmt, TxDesc is first in frame
  pTxDesc = (tMK2TxDescriptor *) ((char *) pBuf);

  switch (pTx->InterfaceID)
  {
    case INTERFACEID_WAVERAW:
      //--------------------------------------------------------------------------
      // WAVE-RAW frame: | TxDesc | Eth Header | Protocol & Payload |
      pEthHdr = (struct ethhdr *) ((char *) pTxDesc + sizeof(tMK2TxDescriptor));
      pPayload = (unsigned char *) ((char *) pEthHdr + sizeof(struct ethhdr));

      // Ethernet Header (SA is already in from Tx_Init())
      memcpy(pEthHdr->h_source, pTx->EthHdr.h_source, ETH_ALEN); // SA
      memcpy(pEthHdr->h_dest, pTxCHOpts->DestAddr, ETH_ALEN); // DA
      pEthHdr->h_proto = htons(pTxCHOpts->EtherType); // EtherType
      break;

    case INTERFACEID_WAVEMGMT:
      //--------------------------------------------------------------------------
      // WAVE-MGMT frame: | TxDesc | 802.11 Header | Protocol & Payload |
      pDot11Hdr = (struct IEEE80211MACHdr *) ((char *) pTxDesc
                                              + sizeof(tMK2TxDescriptor));
      pPayload = (unsigned char *) ((char *) pDot11Hdr
                                    + sizeof(struct IEEE80211MACHdr));

      // Dot11 Header (from preload then set locals)
      // must go into output buffer as little endian
      memcpy(pDot11Hdr, &(pTx->Dot11Hdr), sizeof(struct IEEE80211MACHdr));
      memcpy(pDot11Hdr->Address1, pTxCHOpts->DestAddr, ETH_ALEN); // DA
      break;
    default:
      printf("Fail: Invalid Interface\n");
      ErrCode = TX_ERR_INVALIDINTERFACE;
      return ErrCode;
      break;
  }

  pTx->SocketAddress.sll_protocol = htons(pTxCHOpts->EtherType);

  // Get loops specs for RangeSpec variants
  pTxPowerRangeSpec = &(pTxCHOpts->TxPower);

  // MCS Loop
  for (m = 0; m < pTxCHOpts->NMCS; m++)
  {

    // TxPower Loop through Range
    for (TxPower = pTxPowerRangeSpec->Start; TxPower <= pTxPowerRangeSpec->Stop; TxPower
         += pTxPowerRangeSpec->Step)
    {

      // each range in PackLength list of ranges
      for (r = 0; r < pTxCHOpts->NPacketLengths; r++)
      {
        pPayloadLenRangeSpec = &(pTxCHOpts->PacketLength[r]);

        // Payload Length Loop though Range
        for (PayloadLen = pPayloadLenRangeSpec->Start; PayloadLen
             <= pPayloadLenRangeSpec->Stop; PayloadLen
             += pPayloadLenRangeSpec->Step)
        {

          // Antenna Loop
          for (a = 0; a < pTxCHOpts->NTxAnt; a++)
          {

            // Setup the Mk2Descriptor
            pTxDesc->ChannelNumber = pTxCHOpts->ChannelNumber;
            pTxDesc->Priority = pTxCHOpts->Priority;
            pTxDesc->Service = pTxCHOpts->Service;
            pTxDesc->TxPower.PowerSetting = pTxCHOpts->TxPwrCtrl;
            pTxDesc->TxAntenna = pTxCHOpts->pTxAntenna[a]; // List
            pTxDesc->Expiry = pTxCHOpts->Expiry;
            pTxDesc->MCS = pTxCHOpts->pMCS[m]; // List
            pTxDesc->TxPower.ManualPower = (tMK2Power) TxPower; // from long

            // Setup the user data
            ThisFrameLen = PayloadLen + ((unsigned long) pPayload
                                         - (unsigned long) pBuf);

            // write Payload Bytes according to mode (PayloadValue)
            Payload_gen(pPayload, PayloadLen, pTx->SeqNum,
                        pTxOpts->PayloadMode, pTxOpts->PayloadByte);

            if (0)
            {
              // Replace the header with a WSMP header
              pPayload[0] = 0x02; // Version
              pPayload[1] = 0x00; // PSID

              pPayload[2] = 0x04;
              pPayload[3] = 0x01;
              pPayload[4] = 0xff & (TxPower / 2); // TxPower

              pPayload[5] = 0x10;
              pPayload[6] = 0x01;
              pPayload[7] = 12; // DataRate (12mbps actually 6mbps)

              pPayload[8] = 0x0f;
              pPayload[9] = 0x01;
              pPayload[10] = pTxCHOpts->ChannelNumber; // Channel

              pPayload[11] = 0x80; // WSM element ID

              pPayload[12] = (PayloadLen & 0x0000ff00) >> 8;
              pPayload[13] = (PayloadLen & 0x000000ff) >> 0;
            }

            // The socket is O_NONBLOCK, so poll until it is ready to accept packets
            while (TxContinue)
            {
              struct pollfd Fds[1];
              int Interval;
              int Data;

              Fds[0].fd = pTx->Fd;
              Fds[0].events = POLLOUT | POLLERR | POLLHUP;

              Interval = Pause_us / 1000;
              if (Interval == 0)
                Interval = 1;

              Data = poll(Fds, 1, Interval);
              if (Data < 0) // error
                break;
              else if (Data) // ready
                break;
              else if (Data == 0) // timeout
                continue;
            }

            // Now send the packet
            ThisBytesSent = sendto(pTx->Fd, pBuf, ThisFrameLen, 0, NULL, 0);
            if (ThisBytesSent != ThisFrameLen)
              fprintf(stderr, "sendto(%d) errno %d '%s'\n", ThisFrameLen, errno, strerror(errno));
            else
            {
              // record this packet in Packet Log file as it has now been Txed
              DumpHeadings = (pTx->SeqNum % 20) == 0; // every now & then dump a heading

              Tx_fprintf(pTx->fp, pBuf, ThisFrameLen, pTx->InterfaceID,
                         pTxOpts->DumpPayload, DumpHeadings);

              // also to screen?
              if (pTxOpts->DumpToStdout == true)
              {
                Tx_fprintf(stdout, pBuf, ThisFrameLen, pTx->InterfaceID,
                           pTxOpts->DumpPayload, DumpHeadings);
              }

              (pTx->SeqNum)++; // increment unique ID of packets
            }
            // Wait a little whle before next transmission (attempt to set tx rate)
            usleep(Pause_us);
          } // Tx Antenna List Loop
        } // Frame Length Loop
      } // Range in PacketLength list
    } // Tx Power Loop
  } // MCS Loop


  d_fnend(D_DEBUG, pTx, "(pTx %p) = %d\n", pTx, ErrCode);

  return ErrCode;
} // end of function

/**
 * @brief Rate controlled send of N packets on CCH and SCH
 * @param pTx pointer to Tx Object owning MLME_IF handle and Config
 * @param pTxOpts the options used to config the channels for sending
 * @return Error Code
 *
 * Will transmit at least pTxOpts->NumberOfPackets.
 * Will typically stop just past this number of packets.
 */

tTxErrCode Tx_SendAtRate (tTx * pTx, tTxOpts * pTxOpts)
{
  tTxErrCode ErrCode = TX_ERR_NONE;
  int Pause_us;
  uint32_t RefSeqNum;
  struct timeval t0, t1;
  struct timeval *pt0, *pt1, *ptswap;
  float ThisPeriod_s;
  float ExtraPause_s;
  float ThisRate_pps;
  float TargetRate_pps;
  float OneOnTargetRate;
  /// check and control packet rate this many times per second
  float CheckRate_cps = 1;
  int NPacketsPerCheck; // number of packets between Rate control calcs

  d_assert(pTx != NULL);
  d_assert(pTxOpts->TargetPacketRate_pps > 0);

  // Get dereferenced copy of target rate
  TargetRate_pps = pTxOpts->TargetPacketRate_pps;

  // precompute target period
  OneOnTargetRate = 1.0 / pTxOpts->TargetPacketRate_pps;

  // calculate initial estimate of pause assuming processing takes zero time
  Pause_us = OneOnTargetRate * 1e6;

  // check 2twice a second Half the number of packets per second
  NPacketsPerCheck = (int) (TargetRate_pps / CheckRate_cps);

  // pointer the timeval pointers at the stack memory
  pt0 = &t0;
  pt1 = &t1;
  // initialise the time snapshots and packet number
  gettimeofday(pt0, NULL);
  RefSeqNum = pTx->SeqNum; // Last Update of rate control at this seqnum

  // Continue until signal or transmitted enough packets
  TxContinue = true;
  while ( (pTx->SeqNum < pTxOpts->NumberOfPackets) && (TxContinue) )
  {
    int ThisNPackets;

    // Send the CCH or SCH packets with the new spacing
    Tx_Send(pTx, pTxOpts, Pause_us);

    // how many packets have been transmitted since the last update?
    ThisNPackets = (pTx->SeqNum - RefSeqNum);

    // if many then update rate control
    if (ThisNPackets >= NPacketsPerCheck)
    {

      // Dump the stats from the MLME
      //Tx_DumpStats (stdout, pTx);

      // Now calc private stats
      // how much time has elapsed ?
      // should we adjust the pause to acheive the desired rate?

      gettimeofday(pt1, NULL);
      ThisPeriod_s = (pt1->tv_sec - pt0->tv_sec)
                     + (pt1->tv_usec - pt0->tv_usec) * 1e-6;

      ThisRate_pps = ThisNPackets / ThisPeriod_s; // only calculate for display

      ExtraPause_s = OneOnTargetRate - 1 / ThisRate_pps; //stable when R * N = T

      fprintf(
        stdout,
        "Tx: Last SeqNum: %10d [/%d]. Packet rate: Current %7.1f, Target %7.1f\n",
        pTx->SeqNum, pTxOpts->NumberOfPackets, ThisRate_pps,
        TargetRate_pps);

      d_printf(D_DEBUG, pTx, "Pause Update: %d / %.1f - %.6f = %.6f\n",
               ThisNPackets, TargetRate_pps, ThisPeriod_s, ExtraPause_s);

      Pause_us += (int) (ExtraPause_s * 5e5); // only feedback half of error

      d_printf(D_DEBUG, pTx, "Pause: %d us\n", Pause_us);

      // can't go any faster
      if (Pause_us < 0)
        Pause_us = 0;

      // flip timing pointers and counter
      RefSeqNum = pTx->SeqNum;
      ptswap = pt1;
      pt1 = pt0;
      pt0 = ptswap;
    } // rate control

  } // number of packets


  return ErrCode;

}

/**
 * @brief Forward TZSP encapsulated packets
 * @param pTx pointer to Tx Object
 * @param pTxOpts the options used to config the channels for sending
 * @return Error Code
 *
 *  Ported from J. Buetefuer's MK1 version by P. Alexander Oct 2010
 *    20 Jan 2011: PDA : Added Occasional stdout (count by RateID)
 *
 */
/* this can probably be reduced, it needs to be large enough to hold the largest
 expected TZSP packet, payload and headers. The payload will be at most 4095 bytes
 (max 802.11 frame length), and the TZSP tags and overhead should not be more
 than 100 bytes or so. */
#define TZSP_PKT_BUF_SIZE (6000)
#define PAYLOADOFFSET 27
#define BUFOFFSET 100 // remove to put TxDesc and EthHdr before Payload
tTxErrCode Tx_Forward (tTx * pTx, tTxOpts * pTxOpts)
{
  int sdin; // wait on this socket
  int ret;
  int r; // rate ID loop index
  tTZSPHeader * pTZSPHeader;
  struct sockaddr_in servAddr;
  struct ethhdr *pEthHdr;
  tTxCHOpts * pTxCHOpts;
  struct MK2TxDescriptor *pTxDesc;
  char *pPayload; // Buffer to send out on socket
  int ThisFrameLen, ThisBytesSent; // Number of Bytes
  uint8_t inbuf[TZSP_PKT_BUF_SIZE];
  uint8_t * pBuf; // read from socket into this pointer (offset into buf)
  struct IEEE80211MACHdr *pDot11Hdr;
  // Manual transmit power level (minimum value from power range)
  long CurrentTxPower = 0;
  // Per rate-id counters
  uint32_t TxCountByRateID[16] = { 0 }; // all zero

  if ((pTx == NULL) || (pTxOpts == NULL))
  {
    fprintf(stderr, "ERROR: NULL params\n");
    return -1;
  }

  pBuf = inbuf + BUFOFFSET;

  pTxCHOpts = &(pTxOpts->TxCHOpts);
  d_assert(pTxCHOpts != NULL);

  // Fixed TxPower setting - minimum specified in power range
  CurrentTxPower = pTxCHOpts->TxPower.Start;

  printf("Starting Forwarder\n");
  // inbound socket
  sdin = socket(AF_INET, SOCK_DGRAM, 0);
  if (sdin < 0)
  {
    fprintf(stderr, "ERROR: Failed to open TZSP socket\n");
    return -1;
  }
  printf("Binding port\n");

  // bind local inbound port
  servAddr.sin_family = AF_INET;
  servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servAddr.sin_port = htons(pTxOpts->TZSPPort);
  ret = bind(sdin, (struct sockaddr *) &servAddr, sizeof(servAddr));
  if (ret < 0)
  {
    fprintf(stderr, "ERROR: Failed to bind to TZSP port (%d)\n",
            pTxOpts->TZSPPort);
    return -1;
  }

  printf("Entering Wait Loop\n");

  /* server infinite loop */
  while (1)
  {
    int n;

    /* receive message */
    n = recvfrom(sdin, pBuf, sizeof(inbuf) - BUFOFFSET, 0, NULL, 0);

    if (n < 0)
    {
      fprintf(stderr, "ERROR: recvfrom error\n");
      continue;
    }
    else
    {
      ///  Keep requested per-packet RateID as we will overwrite the buffer containing the TZSP header content
      uint8_t RateID = 0;

      // process received TZSP packet
      TxCountByRateID[0]++; // keep track of total in RateID 0

      // ToDo: generalised parser
      // for now assume according to udptest_packet.build_tzsp_pkt at 5 Oct 2010

      // cast start of received buffer to expected TSZP header structure
      // and check vals
      pTZSPHeader = (tTZSPHeader *) pBuf;
      pPayload = (char *) pBuf + PAYLOADOFFSET;

      /*
       printf("Buffer:\n");
       for (i=0; i<128; i++) {
       printf("%02x ", pBuf[i]);
       if ((i+1)%16==0) printf("\n");
       }
       printf("Payload: ");
       for (i=0; i<16; i++) {
       printf("%02x ", (0xFF & pPayload[i]));
       }
       printf("\n");


       d_printf(D_DEBUG, pTx, "TZSPHeader: Version: %d, Type: %d, Encapsulates: %04x, Magic: %08x, RateID: %02x\n",
       pTZSPHeader->Version,
       pTZSPHeader->Type,
       pTZSPHeader->Encapsulates,
       pTZSPHeader->Magic,
       pTZSPHeader->RateID);
       */
      RateID = pTZSPHeader->RateID & 0x0F;
      TxCountByRateID[RateID]++;

      switch (pTx->InterfaceID)
      {
        case INTERFACEID_WAVERAW:
          //--------------------------------------------------------------------------
          // WAVE-RAW frame: | TxDesc | Eth Header | Protocol & Payload |
          pEthHdr = (struct ethhdr *) ((char *) pPayload
                                       - sizeof(struct ethhdr));
          pTxDesc = (tMK2TxDescriptor *) ((char *) pEthHdr
                                          - sizeof(tMK2TxDescriptor));

          // Ethernet Header (SA is already in from Tx_Init())
          memcpy(pEthHdr->h_source, pTx->EthHdr.h_source, ETH_ALEN); // SA
          memcpy(pEthHdr->h_dest, pTxCHOpts->DestAddr, ETH_ALEN); // DA
          pEthHdr->h_proto = htons(pTxCHOpts->EtherType); // EtherType

          break;
        case INTERFACEID_WAVEMGMT:

          //--------------------------------------------------------------------------
          // WAVE-MGMT frame: | TxDesc | 802.11 Header | Protocol & Payload |
          pDot11Hdr = (struct IEEE80211MACHdr *) ((char *) pPayload
                                                  - sizeof(struct IEEE80211MACHdr));
          pTxDesc = (struct MK2TxDescriptor *) ((char *) pDot11Hdr
                                                - sizeof(tMK2TxDescriptor));

          // Dot11 Header (from preload then set locals)
          // must go into output buffer as little endian
          memcpy(pDot11Hdr, &(pTx->Dot11Hdr), sizeof(struct IEEE80211MACHdr));
          memcpy(pDot11Hdr->Address1, pTxCHOpts->DestAddr, ETH_ALEN); // DA

          break;
        default:
          printf("Fail: Invalid Interface\n");
          return -1;
          break;
      }

      ThisFrameLen = n - PAYLOADOFFSET + (char *) pPayload - (char *) pTxDesc;

      pTx->SocketAddress.sll_protocol = htons(pTxCHOpts->EtherType);

      // Setup the Mk2Descriptor based on the meta data received
      pTxDesc->ChannelNumber = pTxCHOpts->ChannelNumber;
      pTxDesc->Priority = pTxCHOpts->Priority;
      pTxDesc->Service = pTxCHOpts->Service;
      // Use power settings provided via command-line (if specified)
      pTxDesc->TxPower.PowerSetting = pTxCHOpts->TxPwrCtrl;
      pTxDesc->TxPower.ManualPower = (tMK2Power)CurrentTxPower; // from long
      pTxDesc->TxAntenna = pTxCHOpts->pTxAntenna[0];
      pTxDesc->Expiry = pTxCHOpts->Expiry;
      pTxDesc->MCS = RateID; // from tzsp packet in input

      // Now send the packet
      ThisBytesSent = sendto(pTx->Fd, (char *) pTxDesc, ThisFrameLen, 0, NULL,
                             0);

      d_assert(ThisBytesSent == ThisFrameLen);

      // display total count by Rate ID every now and then
      if ((TxCountByRateID[0] & 0x00000FF) == 0xFF)
      {
        for (r = 1; r < 16; r++)
          if (TxCountByRateID[r] > 0)
            printf("Rate %1x: %010d\n", r, TxCountByRateID[r]);
      }

    }
  }

}

/**
 * @brief catch termination of tx to print final stats and exit gracefully
 * @param sig the signal caught
 * Didn't want to use a global Continue variable.
 *
 */
void txsignalhandler (int sig)
{

  // unlock only infinite loop
  TxContinue = false;

}



/**
 * @brief Transmit packets on channels that have already been started
 *
 * In Create Mode:
 *   Open a raw socket to the "wave-raw" network interface.
 *    - Packets are transmitted on the CCH or the SCH via the raw socket to the wave-raw interface, using sendmsg socket function call.
 *    - Selection of SCH or CCH is determined from the ChannelNumber parameter within the transmit descriptor
 * In TZSP Forward Mode:
 *    - Listen on post for udp packets
 *    - Add Tx Desc and send to wave interface
 */
int main (int argc, char* argv[])
{

  tTxOpts TxOpts; // object to hold cmd line config
  tTxOpts * pTxOpts; // pointer to Configuration
  tTx Tx =
  { ~MK2STATUS_SUCCESS, -1, -1 }; // object to hold Tx State
  tTx * pTx; // pointer to Tx State

  // catch all of these signal to terminate Tx
  signal(SIGTERM, &txsignalhandler);
  signal(SIGINT, &txsignalhandler);
  signal(SIGABRT, &txsignalhandler);

  pTx = &Tx; // get pointer to Tx State
  pTxOpts = &TxOpts; // get pointer to Tx Options

  // get the configuration parameters, some may be lists that need to be looped through
  if (TxOpts_New(argc, argv, pTxOpts) < 0)
  {
    TxOpts_PrintUsage();
    return -1;
  }

  TxOpts_Print(pTxOpts);

  // Initialise the Socket to the device to default values
  Tx_Init(pTx, pTxOpts);

  // Open a raw socket to the specified network interface.
  Tx_OpenInterface(pTx, pTxOpts->pInterfaceName);

  switch (pTxOpts->Mode)
  {
    case TXOPTS_MODE_CREATE:
      // Packets are transmitted on the CCH or the SCH via the raw socket to the
      // wave-raw interface, using sendmsg socket function call.
      Tx_SendAtRate(pTx, pTxOpts);
      break;
    case TXOPTS_MODE_TZSPFWD:

      // Listen for TSZP encapsulated packets in the specified port
      // and forward them to the wave if.
      Tx_Forward(pTx, pTxOpts);
      break;
    default:

      break;
  }

  printf("%d Packets Transmitted\n", pTx->SeqNum);
  // Close the opened interface
  Tx_CloseInterface(pTx);

  pTx->Res = MK2STATUS_SUCCESS;
  Tx_Exit(pTx);
  return 0;
}

/**
 * @}
 */
