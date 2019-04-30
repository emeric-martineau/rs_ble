#define BTPROTO_L2CAP 0
#define BTPROTO_HCI   1

#define SOL_HCI       0
#define HCI_FILTER    2

#define HCIGETDEVLIST _IOR('H', 210, int)
#define HCIGETDEVINFO _IOR('H', 211, int)

#define HCI_CHANNEL_RAW     0
#define HCI_CHANNEL_USER    1
#define HCI_CHANNEL_CONTROL 3

#define HCI_DEV_NONE  0xffff

#define HCI_MAX_DEV 16

#define ATT_CID 4