/* 
 * Air Quality PCAP Analyzer
 * by Alex Arendsen, 2015
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define MAX_ENTITIES 250
#define SSID_LENGTH 255
#define TYPE_UNKNOWN 0
#define TYPE_AP 1
#define TYPE_USER 2

// Struct Defs

// One structure for each WiFi entity detected
struct entity {
  u_int64_t mac;      // MAC address of this entity
  u_int64_t apmac;    // For users, MAC address of connected AP
  short int channel;  // Radio 2.4GHz channel (number 1 - 12)
  int nusers;         // For APs, number of connected users
  long unsigned int rxtraffic;  // Bytes of receieved traffic
  long unsigned int txtraffic;  // Bytes of transmitted traffic
  int beacons;        // For APs, number of beacon frames transmitted
  char ssid[255];     // For APs, the SSID this AP is broadcasting on this channel
  int type;           // The entity type, either TYPE_UNKNOWN, TYPE_AP, or TYPE_USER
  int8_t rssi;        // For APs, the RSSI (signal strength) of the first beacon frame
  u_int8_t pktidx;    // The index of the first packet indicating the presence of this entity
};

// One structure for each channel in the 2.4GHz band
struct channel {
  short int channel;       // The index of this channel (1 - 12)
  u_int64_t traffic;       // Bytes of all traffic on this channel
  u_int64_t usage;         // An RSSI-adjusted measurement of the channel's usage
  struct entity* aps[20];  // Array of APs serving on this channel
  short int naps;          // Number of APs serving on this channel
};

// Globals + Constants
int nent = 0;                   // Number of registered entities
struct entity en[MAX_ENTITIES]; // Array of registered entities
long unsigned int pcount = 0;   // Number of packets processed
const char bytesuffixes[] = {'b','k','M','G','T','E','P'};  // byte, kilobyte, etc., for humanbytes()

// Function Prototypes
// -- Finders
struct entity* _find(u_int64_t, int);
struct entity* find_any(u_int64_t);
struct entity* find_ap(u_int64_t);
struct entity* find_user(u_int64_t);
u_char *find_tag(u_char*, u_int8_t, u_int8_t*);

// -- Codec
u_int64_t get_mac(u_char*);
char *decode_mac(u_int64_t);
u_int16_t get_two(u_char*);

// -- Entity Management
struct entity* add_ap(u_int64_t);
void confirm_ap(struct entity*);
struct entity* add_user(u_int64_t);
void confirm_user(struct entity*);
struct entity* add_unknown(u_int64_t);
void set_ap_ssid(struct entity*, u_char*);

// -- Analysis
u_int8_t* grade_aps_by_rssi();
void analyze();
void analyze_channels();
void handle_packet(u_char*, const struct pcap_pkthdr*, const u_char*);
void handle_beacon(u_char*, u_int64_t, int8_t);
void humanbytes(u_int64_t, char*);


// Function Definitions

// Entity finder backend, returns pointer to the entity with the given MAC address,
// given that it exists and has the given type (-1 will match entities of any type)
struct entity* _find(u_int64_t mac, int type) {
  struct entity* wrk = en;
  for (int i = 0; i < nent; ++i) {
    if ((wrk->type==type || type == -1) && wrk->mac == mac) {
      return wrk;
    }
    ++wrk;
  }
  return NULL;
}

struct entity* find_any(u_int64_t mac) { return _find(mac, -1); }
struct entity* find_ap(u_int64_t mac) { return _find(mac, TYPE_AP); }
struct entity* find_user(u_int64_t mac) { return _find(mac, TYPE_USER); }

// MAC addresses are 48 bits, this returns 64 bits; the biggest bits will be zeroed
u_int64_t get_mac(u_char *data) {
  u_int64_t out = 0;
  out = (out | get_two(data)) << 16;
  out = (out | get_two(data + 2)) << 16;
  out = (out | get_two(data + 4));
  return out;
}

// Decode MAC address encoded by get_mac function into a string
char* decode_mac(u_int64_t mac) {
  char *out = calloc(sizeof(char), 18);
  u_int8_t *wrk = (u_int8_t *)&mac;
  for (int i = 0; i < 6; ++i) {
    sprintf(out+(i*3),"%02x:",*(wrk+(5-i)));
  }
  out[17] = '\0';
  return out;
}

// Get two bytes from the pointed input data
u_int16_t get_two(u_char *data) {
  u_int16_t out = ((u_int8_t)data[0] << 8 ) | ((u_int8_t)data[1]);
  return out;
}

// Seek tagged parameter in frame, data should point to beginning of tagged params
// tag_id should be the type of tag to find
u_char *find_tag(u_char* data, u_int8_t tag_id, u_int8_t* size) {
  u_int8_t tag_type = -1;
  u_int8_t tag_length = 0;
  while (tag_type != tag_id) {
    tag_type = (u_int8_t) data[0];
    tag_length = (u_int8_t) data[1];
    if (tag_type != tag_id) {
      data += tag_length + 2;
    } else {
      data += 2;
    }
  }
  *size = tag_length;
  return data;
}

struct entity* add_unknown(u_int64_t mac) {
  if (nent < MAX_ENTITIES) {
    en[nent].mac = mac;
    en[nent].type = TYPE_UNKNOWN;
    en[nent].rxtraffic = 0;
    en[nent].txtraffic = 0;
    return &en[nent++];
  } else {
    fprintf(stderr, "Failed to create new entity, no more room.\n");
    return NULL;
  }
}

struct entity* add_ap(u_int64_t mac) {
  if (nent < MAX_ENTITIES) {
    en[nent].mac = mac;
    en[nent].channel = 0;
    en[nent].rxtraffic = 0;
    en[nent].txtraffic = 0;
    en[nent].type = TYPE_AP;
    return &en[nent++];
  } else {
    fprintf(stderr, "Failed to create new AP, too many records.\n");
    return NULL;
  }
}

void confirm_ap(struct entity* ap) {
  if (ap != NULL) {
    ap->type = TYPE_AP;
  } else {
    fprintf(stderr, "Failed to confirm access point, does not exist.\n");
  }
}

void set_ap_ssid(struct entity* ap, u_char *pkt) {
  u_int8_t ssid_size;
  u_char *ssid_ptr = find_tag(pkt, 0, &ssid_size);
  strncpy(ap->ssid, ssid_ptr, ssid_size);
  ap->ssid[ssid_size] = '\0';
}

struct entity* add_user(u_int64_t mac) {
  if (nent < MAX_ENTITIES) {
    en[nent].mac = mac;
    en[nent].type = TYPE_USER;
    en[nent].rxtraffic = 0;
    en[nent].txtraffic = 0;
  } else {
    fprintf(stderr, "Failed to create new user, too many records.\n");
  }
}

void confirm_user(struct entity* user) {
  if (user != NULL) {
    user->type = TYPE_USER;
  } else {
    fprintf(stderr, "Failed to confirm user, does not exist.\n");
  }
}

void handle_beacon(u_char *pkt, u_int64_t mac, int8_t rssi) {
  struct entity* ap = find_any(mac);
  if (ap == NULL) { ap = add_ap(mac); }
  if (ap->type != TYPE_AP) { confirm_ap(ap); }
  if (ap->channel == 0) {
    // Fill AP record with data from this frame
    pkt+=36;
    u_char* tag_ptr;
    u_int8_t tag_length;

    set_ap_ssid(ap, pkt);
    tag_ptr = find_tag(pkt, 3, &tag_length);
    ap->channel = (u_int8_t) tag_ptr[0];
    ap->rssi = rssi;
  }

  ap->beacons++;
}

void handle_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
  u_int32_t len_rthead = (u_int32_t)(packet + 2)[0]; // Get length of radiotap header
  u_char *pkt_ptr = (u_char *)(packet);

  int8_t rssi = (u_int8_t) pkt_ptr[22];

  pkt_ptr += len_rthead; // Done with radiotap header, moving on
  ++pcount;

  // Get some general frame information
  // Get frame type
  u_int8_t wtype = (u_int8_t) ((pkt_ptr[0] >> 2) & 3);
  u_int8_t wsubtype = (u_int8_t) (pkt_ptr[0] >> 4);
  // Get addresses
  int no_sa = (wtype==1 && (wsubtype == 12 || wsubtype == 13));
  u_int64_t da = get_mac(pkt_ptr + 4);
  u_int64_t sa = get_mac(pkt_ptr + 10);


  if (no_sa) {
    struct entity* dst = find_any(da);
    if (dst == NULL) { dst = add_unknown(da); }
    if (dst == NULL) {
      fprintf(stderr, "Ran out of memory! Skipping CTS recip...\n");
    } else {
      dst->rxtraffic+= header->len;
    }
  } else if (wtype == 0 && wsubtype == 8) {  // Handle beacon frame
    handle_beacon(pkt_ptr, sa, rssi);
  } else {  // Handle other frames

    // Find entity records (create new if non-existent)
    struct entity* src = find_any(sa);
    if (src == NULL) { src = add_unknown(sa); }
    struct entity* dst = find_any(da);
    if (dst == NULL) { dst = add_unknown(da); }
    if (src == NULL || dst == NULL) {
      fprintf(stderr, "Ran out of memory! Your results may not be complete...\n");
    } else {
      int st = src->type;
      int dt = dst->type;


      if (st == dt || st == TYPE_AP || st == TYPE_USER) {
        // Ignore cross-chat, shouldn't be very prevailent anyway
      } else if (st == TYPE_AP && dt == TYPE_UNKNOWN) {
        confirm_user(dst);
        dst->apmac = src->mac;
        dst->pktidx = pcount;
      } else if (st == TYPE_UNKNOWN && dt == TYPE_AP) {
        confirm_user(src);
        src->apmac = dst->mac;
        src->pktidx = pcount;
      }

      src->txtraffic += header->len;
      dst->rxtraffic += header->len;
    }
  }

}

// Produce list of indexes that order APs in descending order by RSSI
u_int8_t *grade_aps_by_rssi() {
  u_int8_t *out = calloc(nent, sizeof(u_int8_t));

  for (int i = 0; i < nent; ++i) { out[i] = i; }
  for (int i = 0; i < nent; ++i) {
    int maxidx = i;
    int swp;
    for (int j = i+1; j < nent; ++j) {
      if (en[out[j]].rssi > en[out[maxidx]].rssi) {
        maxidx = j;
      }
    }
    swp = out[maxidx];
    out[maxidx] = out[i];
    out[i] = swp;
  }

  return out;
}

// Give 4-figure human-readable size (eg, 123456 => 123.4k)
void humanbytes(u_int64_t bytes, char *buffer) {
  if(bytes == 0) {
    sprintf(buffer, "-----");
  } else {
    float num = (float) bytes;
    int magnitude = 0;
    while (num > 1000) {
      ++magnitude;
      num /= 1000.0;
    }
    sprintf(buffer, "%.01f%c", num, bytesuffixes[magnitude]);
  }
}

// Analyze traffic
void analyze() {
  printf("Analysis\n----\n");
  float netshare;
  u_int8_t *graded = grade_aps_by_rssi();
  int idx;
  char bytebuffer[255];
  for (int i = 0; i < nent; ++i) {
    idx = graded[i];
    if (en[idx].type != TYPE_AP) { continue; }

    // Interpret RSSI
    char rssi_descriptor[30];
    int rssi = en[idx].rssi;
    if (rssi > -50) { strcpy(rssi_descriptor,"Excellent"); }
    else if (rssi > -65) { strcpy(rssi_descriptor,"Good"); }
    else if (rssi > -80) { strcpy(rssi_descriptor,"Fair"); }
    else if (rssi > -110) { strcpy(rssi_descriptor,"Poor"); }
    else { strcpy(rssi_descriptor,"No Signal"); }

    // Count users
    for (int j = 0; j < nent; ++j) {
      if (en[j].apmac == en[idx].mac) { ++en[idx].nusers; }
    }
    humanbytes(en[idx].rxtraffic + en[idx].txtraffic, bytebuffer);
    printf(
      "%s | %2d Usr | %6s RxTx | %3d Bcn | Ch %02d | SSID %16s | %s (%ddBm)\n",
      decode_mac(en[idx].mac),
      en[idx].nusers,
      bytebuffer,
      en[idx].beacons,
      en[idx].channel,
      en[idx].ssid,
      rssi_descriptor,
      rssi
    );
    for (int j = 0; j < nent; ++j) { // Print users
      if (en[j].apmac == en[idx].mac) {
        netshare = 100 * ((float) en[j].txtraffic / en[idx].rxtraffic);
        printf("  > ");
        humanbytes(en[j].txtraffic, bytebuffer);
        printf(" %6s (%6.2f%%) | %s", bytebuffer, netshare, decode_mac(en[j].mac));
        printf("\n");
      }
    }

  }

  printf("\n");
}

// Analyze channel usage
void analyze_channels() {
  struct channel chans[12];
  u_int64_t ttot;
  u_int64_t maxtot = 1;
  short int chan;
  int factor;
  float rssi_coeff;
  int cchan;
  char bytebuffer[255];
  for(int i=0;i<12;++i){
    chans[i].naps = 0;
    chans[i].traffic = 0;
    chans[i].usage = 0;
  }

  printf("Channel Analysis\n----\n");
  for (int i = 0; i < nent; ++i) {
    if (en[i].type != TYPE_AP) { continue; }

    chan = en[i].channel - 1;
    factor = 2;
    if(chan <= 12) {
      // Calculate total traffic + apply to tally
      ttot = en[i].rxtraffic + en[i].txtraffic;
      chans[chan].traffic += ttot;
 
      // Increment usage by RSSI-attenuated traffic
      rssi_coeff = (float) (en[i].rssi + 110) / 70;
      if(rssi_coeff > 1) { rssi_coeff = 1.0f; }
      else if (rssi_coeff < 0) {rssi_coeff = 0.0f;}
      ttot *= rssi_coeff;
      chans[chan].usage += ttot;

      // Add this AP to its channel's list
      chans[chan].aps[chans[chan].naps] = &en[i];
      chans[chan].naps++;
      for(int j = 1; j <= 3; ++j) {
        if(chan-j >= 0) { chans[chan-j].usage += ttot/factor; }
        if(chan+j <= 12) { chans[chan+j].usage += ttot/factor; }
        factor *= factor;
      }

      ttot = chans[chan].usage;
      if (ttot > maxtot) { maxtot = ttot; }
    }
  }

  for (int i = 0; i < 12; ++i) {
    humanbytes(chans[i].traffic,bytebuffer);
    printf("\nChannel %3d: %6s %2d APs :: ", i+1, bytebuffer, chans[i].naps);
    // Print histogram of channel usage
    for(int j=((48 * chans[i].usage)/maxtot);j > 0; --j) {
      printf("|");
    }
  }
}

// Driver
int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <pcap file 1> ... <pcap file n> \n", argv[0]);
    return 1;
  }

  for (int i = 1; i < argc; ++i) {
    pcap_t *pcap;
    char error[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_offline(argv[i], error);

    if (pcap == NULL) {
      fprintf(stderr, "%s: Failed to open pcap file: %s\n", argv[i], error);
      continue;
    }

    pcap_loop(pcap, -1, handle_packet, NULL);
    
    pcap_close(pcap);
  }

  analyze();
  analyze_channels();

  printf("\nAll files read, quitting.\n");

  
  return 0;
}
