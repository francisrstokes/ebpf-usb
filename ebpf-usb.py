#!/usr/bin/env -S python3 -u

from bcc import BPF
from hexdump import hexdump

import termios
import sys
import atexit
import argparse

parser = argparse.ArgumentParser(description='Monitor USB traffic using eBPF')
parser.add_argument('--vendor-id', '-v', type=lambda x: int(x, 16), help='The vendor id, expressed in hex')
parser.add_argument('--product-id', '-p', type=lambda x: int(x, 16), help='The product id, expressed in hex')
parser.add_argument('--out-only', '-o', action='store_true', help='Filter out all incoming messages')
parser.add_argument('--in-only', '-i', action='store_true', help='Filter out all outgoing messages')

args = parser.parse_args()

vid_pid_check = ""
if args.vendor_id is not None and args.product_id is not None:
	vid_pid_check = "if (urb->dev->descriptor.idVendor != %d || urb->dev->descriptor.idProduct != %d) { return 0; }" % (args.vendor_id, args.product_id)
elif args.vendor_id is not None:
	vid_pid_check = "if (urb->dev->descriptor.idVendor != %d) {{ return 0; }}" % (args.vendor_id)
elif args.product_id is not None:
	vid_pid_check = "if (urb->dev->descriptor.idProduct != %d) {{ return 0; }}" % (args.product_id)

endpoint_dir_check = ""
if args.out_only and args.in_only:
	pass
elif args.out_only:
	endpoint_dir_check = "if (urb->transfer_flags & 0x0200) { return 0; }"
elif args.in_only:
	endpoint_dir_check = "if (~(urb->transfer_flags & 0x0200)) { return 0; }"

code = """
#include <linux/usb.h>

struct data_t {
	u64 alen;
	u64 buflen;
	u16 vendor;
	u16 product;
	u8 endpoint;
	unsigned int transfer_flags;
	u8 bmAttributes;
	u8 buf [4096];
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(data_struct, struct data_t, 1);

int kprobe____usb_hcd_giveback_urb(struct pt_regs *ctx, struct urb *urb) {
	// Perform a VID/PID check if configured to do so
	%s
	// Perform endpoint type filtering if configured to do so
	%s

	int zero = 0;
	struct data_t* data = data_struct.lookup(&zero);
	if (!data)
		return 0;

	struct usb_device *dev = urb->dev;

	data->vendor = dev->descriptor.idVendor;
	data->product = dev->descriptor.idProduct;
	data->alen = urb->actual_length;
	data->transfer_flags = urb->transfer_flags;
	data->buflen = urb->transfer_buffer_length;
	data->endpoint = urb->ep->desc.bEndpointAddress;
	data->bmAttributes = urb->ep->desc.bmAttributes;

	bpf_probe_read_kernel(&data->buf, sizeof(data->buf), urb->transfer_buffer);
	events.perf_submit(ctx, data, sizeof(*data));

	return 0;
}
""" % (vid_pid_check, endpoint_dir_check)

b = BPF(text=code)
event_number = 0

def print_event(cpu, data, size):
	global event_number
	event = b["events"].event(data)
	event_number += 1
	print("%d: %04x:%04x [0x%02x %s] (%s) actual length = %d, buffer length = %d"
		% (
			event_number,
			event.vendor,
			event.product,
			event.endpoint,
			get_endpoint_type(event.transfer_flags),
			get_transfer_type(event.bmAttributes),
			event.alen,
			event.buflen
		))
	hexdump(bytes(event.buf[0:event.buflen]))
	print("")

USB_ENDPOINT_XFERTYPE_MASK 	= 0x03
USB_ENDPOINT_XFER_CONTROL 	= 0
USB_ENDPOINT_XFER_ISOC 		= 1
USB_ENDPOINT_XFER_BULK 		= 2
USB_ENDPOINT_XFER_INT 		= 3

def get_transfer_type(bmAttributes):
	masked = bmAttributes & USB_ENDPOINT_XFERTYPE_MASK
	if masked == USB_ENDPOINT_XFER_CONTROL:
		return "CONTROL"
	elif masked == USB_ENDPOINT_XFER_ISOC:
		return "ISOC"
	elif masked == USB_ENDPOINT_XFER_BULK:
		return "BULK"
	else:
		return "INT"

def get_endpoint_type(transfer_flags):
	if transfer_flags & 0x0200:
		return "IN"
	return "OUT"

def set_echo_enabled(fd, enabled):
	(iflag, oflag, cflag, lflag, ispeed, ospeed, cc) = termios.tcgetattr(fd)
	if enabled:
		lflag |= termios.ECHO
	else:
		lflag &= ~termios.ECHO
	new_attr = [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]
	termios.tcsetattr(fd, termios.TCSANOW, new_attr)

VID = ("0x%x" % args.vendor_id) if args.vendor_id is not None else "unspecified"
PID = ("0x%x" % args.product_id) if args.product_id is not None else "unspecified"

print("Starting capture [VID=%s and PID=%s]" % (VID, PID))
set_echo_enabled(sys.stdin.fileno(), False)
atexit.register(set_echo_enabled, sys.stdin.fileno(), True)

b["events"].open_perf_buffer(print_event)
while 1:
	b.perf_buffer_poll()
