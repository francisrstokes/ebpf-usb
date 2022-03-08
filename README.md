# ebpf-usb

Heavily based on: https://github.com/gpioblink/ebpf-usb-inspector

## Usage

```
usage: ebpf-usb.py [-h] [--vendor-id VENDOR_ID] [--product-id PRODUCT_ID] [--out-only] [--in-only]

Monitor USB traffic using eBPF

options:
  -h, --help            show this help message and exit
  --vendor-id VENDOR_ID, -v VENDOR_ID
                        The vendor id, expressed in hex
  --product-id PRODUCT_ID, -p PRODUCT_ID
                        The product id, expressed in hex
  --out-only, -o        Filter out all incoming messages
  --in-only, -i         Filter out all outgoing messages
```

## Example output

```
Starting capture [VID=unspecified and PID=unspecified]
1: [0x0 IN] actual length = 4, buffer length = 4
00000000: 00 01 00 00                                       ....

2: [0x0 IN] actual length = 4, buffer length = 4
00000000: 00 01 00 00                                       ....

3: [0x0 IN] actual length = 4, buffer length = 4
00000000: 07 05 00 00                                       ....

4: [0x0 IN] actual length = 4, buffer length = 4
00000000: 00 01 00 00                                       ....

5: [0x0 IN] actual length = 4, buffer length = 4
00000000: 00 01 00 00                                       ....

6: [0x0 IN] actual length = 4, buffer length = 4
00000000: 00 01 00 00                                       ....

7: [0x0 IN] actual length = 4, buffer length = 4
00000000: 00 01 00 00                                       ....

8: [0x0 IN] actual length = 4, buffer length = 4
00000000: 00 01 00 00                                       ....

9: [0x0 IN] actual length = 4, buffer length = 4
00000000: 07 01 00 00                                       ....

10: [0x0 IN] actual length = 4, buffer length = 4
00000000: 00 01 00 00                                       ....

11: [0x0 IN] actual length = 4, buffer length = 4
00000000: 00 01 00 00                                       ....

12: [0x0 IN] actual length = 4, buffer length = 4
00000000: 00 01 00 00                                       ....

13: [0x0 IN] actual length = 4, buffer length = 4
00000000: 07 05 00 00                                       ....

14: [0x0 OUT] actual length = 0, buffer length = 0

15: [0x81 IN] actual length = 2, buffer length = 4
00000000: 10 00 00 00                                       ....

16: [0x0 IN] actual length = 4, buffer length = 4
00000000: 03 05 04 00                                       ....
```