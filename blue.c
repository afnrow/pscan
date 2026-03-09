#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

void scanbl() {
  int dev_id = hci_get_route(NULL);
  int sock = hci_open_dev(dev_id);
  if (dev_id < 0 || sock < 0) {
    perror("Failed to open HCI device");
    exit(1);
  }
  hci_le_set_scan_parameters(sock, 0x01, htobs(0x0010), htobs(0x0010), 0x00,
                             0x00, 1000);
  hci_le_set_scan_enable(sock, 0x01, 0x00, 1000);

  printf("Scanning for BLE devices...\n");

  struct hci_filter filter;
  hci_filter_clear(&filter);
  hci_filter_set_ptype(HCI_EVENT_PKT, &filter);
  hci_filter_set_event(EVT_LE_META_EVENT, &filter);
  setsockopt(sock, SOL_HCI, HCI_FILTER, &filter, sizeof(filter));

  unsigned char buf[HCI_MAX_EVENT_SIZE];

  while (1) {
    int len = read(sock, buf, sizeof(buf));
    if (len < 0)
      break;
    evt_le_meta_event *meta =
        (evt_le_meta_event *)(buf + HCI_EVENT_HDR_SIZE + 1);
    if (meta->subevent != EVT_LE_ADVERTISING_REPORT)
      continue;
    le_advertising_info *info = (le_advertising_info *)(meta->data + 1);

    char addr[18];
    ba2str(&info->bdaddr, addr);

    printf("Device: %s | RSSI: %d dBm | Data len: %d\n", addr,
           (int8_t)info->data[info->length], // RSSI is after data
           info->length);

    printf("  Raw: ");
    for (int i = 0; i < info->length; i++)
      printf("%02x ", info->data[i]);
    printf("\n");
  }

  hci_le_set_scan_enable(sock, 0x00, 0x00, 1000);
  hci_close_dev(sock);
}
