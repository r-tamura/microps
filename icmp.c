#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

#define ICMP_BUFSIZ IP_PAYLOAD_SIZE_MAX

struct icmp_hdr
{
  uint8_t type;
  uint8_t code;
  uint16_t sum;
  uint32_t values;
};

struct icmp_echo
{
  uint8_t type;
  uint8_t code;
  uint16_t sum;
  uint16_t id;
  uint16_t seq;
};

static char *
icmp_type_ntoa(uint8_t type)
{
  switch (type)
  {
  case ICMP_TYPE_ECHOREPLY:
    return "EchoReply";
  case ICMP_TYPE_DEST_UNREACH:
    return "DestinationUnreachable";
  case ICMP_TYPE_SOURCE_QUENCH:
    return "SourceQuench";
  case ICMP_TYPE_REDIRECT:
    return "Redirect";
  case ICMP_TYPE_ECHO:
    return "Echo";
  case ICMP_TYPE_TIME_EXCEEDED:
    return "TimeExceeded";
  case ICMP_TYPE_PARAM_PROBLEM:
    return "ParameterProblem";
  case ICMP_TYPE_TIMESTAMP:
    return "Timestamp";
  case ICMP_TYPE_TIMESTAMPREPLY:
    return "TimestampReply";
  case ICMP_TYPE_INFO_REQUEST:
    return "InformationRequest";
  case ICMP_TYPE_INFO_REPLY:
    return "InformationReply";
  }
  return "Unknown";
}

static void
icmp_dump(const uint8_t *data, size_t len)
{
  struct icmp_hdr *hdr;
  struct icmp_echo *echo;

  flockfile(stderr);
  hdr = (struct icmp_hdr *)data;
  fprintf(stderr, "       type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
  fprintf(stderr, "       code: %u\n", hdr->code);
  fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
  switch (hdr->type)
  {
  case ICMP_TYPE_ECHOREPLY:
  case ICMP_TYPE_ECHO:
    echo = (struct icmp_echo *)hdr;
    fprintf(stderr, "          id: %u\n", ntoh16(echo->id));
    fprintf(stderr, "         seq: %u\n", ntoh16(echo->seq));
    break;
  default:
    fprintf(stderr, "      values: 0x%08x\n", ntoh32(hdr->values));
    break;
  }

#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif

  funlockfile(stderr);
}

void icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
  struct icmp_hdr *hdr;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];

  /* Exercise 10-1: ICMPメッセージの検証 */
  hdr = (struct icmp_hdr *)data;
  if (len < ICMP_HDR_SIZE)
  {
    errorf("too short, len=%zu", len);
    return;
  }

  // ICMPヘッダのチェックサムはヘッダーとペイロードを含めたもの
  if (cksum16((uint16_t *)data, len, 0) != 0)
  {
    errorf("invalid checksum");
    return;
  }

  /* Exercise 10-1 end */
  debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
  icmp_dump(data, len);
  switch (hdr->type)
  {
  case ICMP_TYPE_ECHO:
    /* Exercise 11-3: ICMPの出力関数を呼び出す */
    // 元々の送信先（dst）がブロードキャストアドレスのときもあるので、返信の送信元は自身のインタフェースのユニキャストアドレスにする
    icmp_output(ICMP_TYPE_ECHOREPLY, 0, hdr->values, (uint8_t *)(hdr + 1), len - ICMP_HDR_SIZE, iface->unicast, src);
    /* Exercise 11-3 end */
    break;
  default:
    /* ignore */
    break;
  }
}

int icmp_output(uint8_t type, uint8_t code, uint32_t values, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
  uint8_t buf[ICMP_BUFSIZ];
  struct icmp_hdr *hdr;
  size_t msg_len; /* ICMPメッセージの長さ（ヘッダ+データ）*/
  char addr[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];

  hdr = (struct icmp_hdr *)buf;

  /* Exercise 11-1: ICMPメッセージの生成 */
  hdr->type = type;
  hdr->code = code;
  hdr->sum = 0;
  hdr->values = hton32(values);
  memcpy(hdr + 1, data, len);
  msg_len = ICMP_HDR_SIZE + len;
  hdr->sum = cksum16((uint16_t *)buf, msg_len, 0);
  /* Exercise 11-1 end */

  debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr, sizeof(addr)), ip_addr_ntop(dst, addr2, sizeof(addr2)), msg_len);
  icmp_dump(buf, msg_len);

  /* Exercise 11-2: IPの出力関数を呼び出してメッセージを送信 */
  return ip_output(IP_PROTOCOL_ICMP, buf, msg_len, src, dst);
  /* Exercise 11-2 end */
}

int icmp_init(void)
{
  /* Exercise 9-4: ICMPの入力関数（icmp_input）をIPに登録 */
  ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input);
  /* Exercise 9-4 end */
  return 0;
}