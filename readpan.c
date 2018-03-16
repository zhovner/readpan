#include <stdlib.h>
#include <string.h>
#include <nfc/nfc.h>

void
PrintHex(uint8_t * data, size_t datalen)
{
  size_t i;

  for(i = 0; i < datalen; i++) {
    printf("%02x ", data[i]);
  }
  puts("");
}

// To send APDUs, we'll use a little helper function with some debugging prints of exchanged APDUs:

int
CardTransmit(nfc_device *pnd, uint8_t * capdu, size_t capdulen, uint8_t * rapdu, size_t * rapdulen)
{
  int res;
  size_t  szPos;
  printf("=> ");
  for (szPos = 0; szPos < capdulen; szPos++) {
    printf("%02x ", capdu[szPos]);
  }
  printf("\n");
  if ((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, 500)) < 0) {
    return -1;
  } else {
    *rapdulen = (size_t) res;
    printf("<= ");
    for (szPos = 0; szPos < *rapdulen; szPos++) {
      printf("%02x ", rapdu[szPos]);
    }
    printf("\n");
    return 0;
  }
}

int
GetAID(uint8_t * data, size_t datalen, uint8_t * aid)
{
  int datapos;

  for (datapos = 1; datapos < datalen; datapos++) {
    if (data[datapos-1] == 0x4F && data[datapos] == 0x07) {
      // if found AID marker
      if (datalen-datapos > 7) {
        memcpy(aid, &(data[datapos+1]), 7);
        return 1;
      }
      break;
    }
  }
  return 0;
}

// https://rosettacode.org/wiki/Luhn_test_of_credit_card_numbers#C
int
luhn(const uint8_t * cc)
{
  const int m[] = {0,2,4,6,8,1,3,5,7,9}; // mapping for rule 3
  int i, odd = 1, sum = 0;

  for (i = strlen(cc); i--; odd = !odd) {
      int digit = cc[i] - '0';
      sum += odd ? digit : m[digit];
  }

  return sum % 10 == 0;
}


int
ValidateStartAID(uint8_t * data, size_t datalen)
{
  if (datalen < 2)
    return 0;

  if (data[0] == 0x6F) {
    if (data[datalen - 2] == 0x90 && data[datalen - 1] == 0x00)
    {
      return 1;
    }
  }
  return 0;
}

int
ValidateAndGetPAN(uint8_t * data, size_t datalen, uint8_t * pan_data)
{
  int datapos, i;
  uint8_t pan_str[17] = {0};

  if (datalen < 4)
    return 0;

  for (datapos = 2; datapos < datalen; datapos++) {
    if (
      (data[datapos-2] == 0x9F && data[datapos-1] == 0x6B && data[datapos] == 0x13) ||
      (data[datapos-1] == 0x5A && data[datapos] == 0x08) ||
      (data[datapos-1] == 0x57 && data[datapos] == 0x13)
    )
    {
      // if found one of conditions
      if (datalen-datapos > 8) {
        memcpy(pan_data, &(data[datapos+1]), 8);
        for (i=0; i<8; i++) {
          sprintf(&(pan_str[i*2]), "%02", pan_data[i]);
        }
        pan_str[16] = '\0';
        // validate luhn
        if (!luhn(pan_str))
          continue;
        return 1;
      }
      break;
    }
  }
  return 0;
}


int
main(int argc, const char *argv[])
{
  uint8_t startAID[] = {0x00, 0xa4, 0x04, 0x00, 0x07};
  uint8_t apdupan[][5] = {
    {0x00, 0xB2, 0x01, 0x1C, 0x00},
    {0x00, 0xb2, 0x01, 0x0c, 0x00},
    {0x00, 0xb2, 0x02, 0x0c, 0x00},
    {0x00, 0xb2, 0x01, 0x14, 0x00},
    {0x00, 0xb2, 0x02, 0x14, 0x00},
    {0x00, 0xb2, 0x04, 0x14, 0x00},
  };
  nfc_device *pnd;
  nfc_target nt;
  nfc_context *context;
  uint8_t aid[7];
  uint8_t pan_data[8];
  int i;

  nfc_init(&context);
  if (context == NULL) {
    printf("Unable to init libnfc (malloc)\n");
    exit(EXIT_FAILURE);
  }
  const char *acLibnfcVersion = nfc_version();
  (void)argc;
  printf("%s uses libnfc %s\n", argv[0], acLibnfcVersion);

  pnd = nfc_open(context, NULL);

  if (pnd == NULL) {
    printf("ERROR: %s", "Unable to open NFC device.");
    exit(EXIT_FAILURE);
  }
  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    exit(EXIT_FAILURE);
  }

  printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

  const nfc_modulation nmMifare = {
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106,
  };
  // nfc_set_property_bool(pnd, NP_AUTO_ISO14443_4, true);
  printf("Polling for target...\n");
  while (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0);
  printf("Target detected!\n");
  uint8_t capdu[264];
  size_t capdulen;
  uint8_t rapdu[264];
  size_t rapdulen;

  // Select application PPSE
  memcpy(capdu, "\x00\xA4\x04\x00\x0E\x32\x50\x41\x59\x2E\x53\x59\x53\x2E\x44\x44\x46\x30\x31\x00", 20);
  capdulen=20;
  rapdulen=sizeof(rapdu);
  if (CardTransmit(pnd, capdu, capdulen, rapdu, &rapdulen) < 0)
    exit(EXIT_FAILURE);
  if (rapdulen < 2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00)
    exit(EXIT_FAILURE);
  printf("Application selected!\n");

  if (!GetAID(rapdu, rapdulen, aid)) {
    puts("Can't get AID!");
    exit(EXIT_FAILURE);
  }
  printf("AID: ");
  PrintHex(aid, 7);

  memcpy(capdu, startAID, sizeof(startAID));
  memcpy(capdu+sizeof(startAID), aid, sizeof(aid));
  capdulen=sizeof(startAID)+sizeof(aid);
  rapdulen=sizeof(rapdu);

  if (CardTransmit(pnd, capdu, capdulen, rapdu, &rapdulen) < 0)
    exit(EXIT_FAILURE);

  if (!ValidateStartAID(rapdu, rapdulen)) {
    puts("Can't validate AID!");
    exit(EXIT_FAILURE);
  }

  for (i = 0; i < sizeof(apdupan) / sizeof(*apdupan); i++) {
    capdulen=sizeof(apdupan[i]);
    rapdulen=sizeof(rapdu);

    if (CardTransmit(pnd, apdupan[i], capdulen, rapdu, &rapdulen) < 0)
      exit(EXIT_FAILURE);

    if (ValidateAndGetPAN(rapdu, rapdulen, pan_data)) {
      printf("Found PAN: ");
      PrintHex(pan_data, 8);
      break;
    }
  }

  printf("\n");
  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}

