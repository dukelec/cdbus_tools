CDBUS / CDNET dissector for Wireshark
=======================================

`cdbus.lua` decodes CDBUS frames and the CDNET packets inside them (cdnet 2.1), from:

 - the `.pcapng` files that [cdbus_gui](https://github.com/dukelec/cdbus_gui) records
   ("Record" on its index page) or `cdbus_terminal.py --record` of this repository writes, the
   format is described below;
 - a capture taken by Wireshark itself on the IPv6/UDP side of the bus, the `tun0` of
   [cdnet_tun](https://github.com/dukelec/cdnet_tun) or the `cdbus0` ethernet port of the
   [CDBUS Bridge](https://github.com/dukelec/cdbus_bridge): a UDP packet with an address
   under `fdcd::/104` is taken as a CDNET packet, the last 3 bytes of the IPv6 addresses are
   the CDNET addresses and the UDP ports the CDNET ports, with the host's `port_offset`
   (`0xcd00`) taken off.

Shown: the CDBUS header and the CRC (checked), the CDNET level, the addresses the tools write
(`00:NN:MM`, `80:NN:MM`, `a0:NN:MM`, `90:MH:ML`, `b0:MH:ML`), the ports, and what the packet does
on the ports the tools use: register reads and writes with the address (port 5), flash commands
(port 8), the device info (port 1) and debug text (port 9). The Source and Destination columns
carry the CDNET addresses, the frame's direction (sent or received) is in its frame details.


Install
------------------------

Copy `cdbus.lua` into the personal Lua plugins folder, listed under Help > About Wireshark >
Folders, then restart Wireshark (or Analyze > Reload Lua Plugins):

| | |
|-|-|
| Linux   | `~/.local/lib/wireshark/plugins/` |
| Windows | `%APPDATA%\Wireshark\plugins\` |
| macOS   | `~/.config/wireshark/plugins/` |

or for one run:

```
wireshark -X lua_script:cdbus.lua cdbus_20260101_120000.pcapng
```

Wireshark has to be built with Lua, which the official Windows and macOS builds are; on a
distribution build check `tshark -v` for "with Lua".

Preferences (Edit > Preferences > Protocols > CDNET): the local net, which a level 0 packet and a
local link level 1 packet do not carry (the `--local-net` of cdbus_gui, 0 by default); the IPv6
prefix and the port offset of the UDP mapping.

Useful filters: `cdnet.dst_port == 5`, `cdnet.src == "80:00:fe"`, `cdnet.reg.addr == 0x10`,
`cdnet.text contains "err"`, `cdmark`, `cdbus.crc.bad`.


The recording format
------------------------

A recording is a pcapng file, nanosecond timestamps, with two interfaces:

| id | link type | name | holds |
|----|-----------|------|-------|
| 0 | `LINKTYPE_USER0` (147) | `cdbus` | one CDBUS frame per packet, as it is on the wire: `src, dst, len, [payload], crc_l, crc_h`. The `epb_flags` option carries the direction: 1 inbound (received from the bus), 2 outbound (sent). |
| 1 | `LINKTYPE_USER1` (148) | `mark` | a mark: the packet data is the mark text (UTF-8), and the same text is the packet comment, so it reads the same without the dissector. |

The section header's `shb_userappl` names the writer (`cdbus_gui <version>`, `cdbus_terminal`),
the `cdbus` interface's description names the serial port, its baud rate and, for cdbus_gui, the
local address of the writer. A frame without the CRC (`len + 3` bytes) is accepted by the
dissector as well. The writer is `cdnet/utils/pcapng.py` of [pycdnet](https://github.com/dukelec/pycdnet).

The link types are from the private range until an official `LINKTYPE_CDBUS` is assigned; the
dissector will then register both.


Test
------------------------

`test_dissector.lua` runs the dissector against a stand-in for the parts of the Wireshark Lua API
it uses, so it needs no Wireshark, only a Lua interpreter (5.2 to 5.4):

```
lua wireshark/test_dissector.lua       # -v prints every tree
```

The stand-in is stricter than Wireshark about field sizes and ranges, on purpose.
