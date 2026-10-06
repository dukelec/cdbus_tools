-- cdbus.lua: CDBUS / CDNET dissector for Wireshark
--
-- Software License Agreement (MIT License)
--
-- Author: Duke Fong <d@d-l.io>
--
-- Opens the pcapng files cdbus_gui records (index page, Record):
--   link type USER0 (147): cdbus frames as they are on the wire,
--                          src, dst, len, [payload], crc_l, crc_h (the crc is checked), the
--                          payload a cdnet packet, level 0 or level 1 (cdnet 2.1)
--   link type USER1 (148): the marks, Enter in a Logs window of the tool or its api, the data
--                          is the mark text
-- A frame without the crc (len + 3 bytes) is taken as well.
--
-- It also decodes a capture made on the IPv6/UDP side of cdnet_tun (tun0) or of the CDBUS
-- Bridge's ethernet port (cdbus0): there the bus is mapped into fdcd::/104, the last 3 bytes of
-- an address are the cdnet address level:net:mac, the UDP port is the cdnet port, and the host's
-- own port is shifted up by port_offset (0xcd00). A UDP packet with either address inside the
-- prefix is taken as a cdnet packet, the payload being the data with no cdnet header, and the
-- addresses and ports in the tree are the cdnet ones the tool uses, so the same filters apply.
--
-- Install: copy this file into the personal Lua plugins folder, which Help > About Wireshark >
-- Folders lists, then restart Wireshark (or Analyze > Reload Lua Plugins):
--   Linux:   ~/.local/lib/wireshark/plugins/
--   Windows: %APPDATA%\Wireshark\plugins\
--   macOS:   ~/.config/wireshark/plugins/
-- or for one run:  wireshark -X lua_script:cdbus.lua records/cdbus_xxx.pcapng
-- Readme.md next to this file describes the recording format; test_dissector.lua checks the
-- dissector without Wireshark (lua wireshark/test_dissector.lua).
--
-- Edit > Preferences > Protocols > CDNET: the local net, which a level 0 packet and a local
-- link level 1 packet do not carry, the way --local-net of the backend fills it in; the IPv6
-- prefix and the port offset of the UDP mapping, the values of cdnet_tun and of the bridge.
--
-- Columns: Source and Destination show the cdnet addresses, Info the ports and what the
-- packet does. Filters: cdbus.src, cdbus.dst, cdnet.src, cdnet.dst, cdnet.src_port,
-- cdnet.dst_port, cdnet.data, cdnet.text, cdnet.reg.addr, cdmark.text ...

-- Lua 5.2 (Wireshark before 4.4) has bit32 and no bitwise operators, Lua 5.3 / 5.4 the other
-- way round. The operators are compiled from a string, so a 5.2 parser never sees them.
local band, bxor, rshift
if bit32 then
    band, bxor, rshift = bit32.band, bit32.bxor, bit32.rshift
elseif bit then
    band, bxor, rshift = bit.band, bit.bxor, bit.rshift
else
    band = load("return function(a, b) return a & b end")()
    bxor = load("return function(a, b) return a ~ b end")()
    rshift = load("return function(a, n) return a >> n end")()
end

-- modbus crc16, the same one the bus uses: appended little endian, the crc of the whole frame is 0
local CRC_TAB = {}
for i = 0, 255 do
    local c = i
    for _ = 1, 8 do
        if band(c, 1) == 1 then
            c = bxor(rshift(c, 1), 0xa001)
        else
            c = rshift(c, 1)
        end
    end
    CRC_TAB[i] = c
end

local function modbus_crc(s)
    local crc = 0xffff
    for i = 1, #s do
        crc = bxor(rshift(crc, 8), CRC_TAB[band(bxor(crc, s:byte(i)), 0xff)])
    end
    return crc
end

local function hex(s, sep)
    local t = {}
    for i = 1, #s do
        t[i] = string.format("%02x", s:byte(i))
    end
    return table.concat(t, sep or " ")
end

-- a device's text for the Info column: colour codes out, line breaks shown, cut to a line
local function printable(s, max)
    s = s:gsub("\27%[[%d;]*[A-Za-z]", "")
    s = s:gsub("\r", ""):gsub("\n$", ""):gsub("\n", " | ")
    s = s:gsub("[%c]", ".")
    max = max or 120
    if #s > max then
        s = s:sub(1, max) .. "..."
    end
    return s
end

local function hex_brief(s, max)
    max = max or 24
    if #s <= max then
        return hex(s)
    end
    return hex(s:sub(1, max)) .. " ..."
end


-- ---------------------------------------------------------------- cdbus

local p_cdbus = Proto("cdbus", "CDBUS Frame")

local f_src = ProtoField.uint8("cdbus.src", "Source MAC", base.HEX)
local f_dst = ProtoField.uint8("cdbus.dst", "Destination MAC", base.HEX)
local f_len = ProtoField.uint8("cdbus.len", "Payload Length", base.DEC)
local f_crc = ProtoField.uint16("cdbus.crc", "CRC", base.HEX)
p_cdbus.fields = { f_src, f_dst, f_len, f_crc }

local e_crc = ProtoExpert.new("cdbus.crc.bad", "CRC does not match",
                              expert.group.CHECKSUM, expert.severity.ERROR)
local e_len = ProtoExpert.new("cdbus.len.bad", "Frame length does not match the length byte",
                              expert.group.MALFORMED, expert.severity.ERROR)
p_cdbus.experts = { e_crc, e_len }


-- ---------------------------------------------------------------- cdnet

local p_cdnet = Proto("cdnet", "CDNET Packet")

p_cdnet.prefs.local_net = Pref.uint("Local net", 0,
    "The net of the bus the capture was made on; a level 0 packet and a local link level 1 " ..
    "packet carry no net, this one is shown for them (the --local-net of cdbus_gui).")
p_cdnet.prefs.prefix = Pref.string("IPv6 prefix of the UDP mapping", "fdcd::",
    "cdnet_tun and the CDBUS Bridge map the bus into this /104: a UDP packet with an address " ..
    "under it is taken as a cdnet packet.")
p_cdnet.prefs.port_offset = Pref.uint("Port offset of the UDP mapping", 0xcd00,
    "The host's own UDP port is its cdnet port plus this (0xcd00 for cdnet_tun and the bridge, " ..
    "0 when switched off): a port at or above it is shown with the offset taken off.")

-- the ports cdbus_gui's devices use, for the Info column
local PORT_NAMES = {
    [0x1] = "dev_info",
    [0x5] = "reg",
    [0x8] = "flash",
    [0x9] = "dbg",
    [0xa] = "plot",
}

local VALS_LEVEL = { [0] = "Level 0", [1] = "Level 1" }
local VALS_REG_CMD = { [0x00] = "read", [0x20] = "write", [0xa0] = "write, no reply" }
local VALS_FLASH_CMD = { [0x00] = "read", [0x20] = "write", [0xa0] = "write, no reply",
                         [0x2f] = "erase", [0x10] = "read crc" }

local f_level     = ProtoField.uint8("cdnet.level", "Level", base.DEC, VALS_LEVEL, 0x80)
local f_hdr       = ProtoField.uint8("cdnet.hdr", "Header", base.HEX)
local f_multi_net = ProtoField.bool("cdnet.multi_net", "Multi Net", 8, nil, 0x20)
local f_multicast = ProtoField.bool("cdnet.multicast", "Multicast", 8, nil, 0x10)
local f_reserved  = ProtoField.uint8("cdnet.reserved", "Reserved", base.HEX, nil, 0x4c)
local f_src_p16   = ProtoField.bool("cdnet.src_port_16", "Source Port 16 bit", 8, nil, 0x02)
local f_dst_p16   = ProtoField.bool("cdnet.dst_port_16", "Destination Port 16 bit", 8, nil, 0x01)
local f_src_net   = ProtoField.uint8("cdnet.src_net", "Source Net", base.HEX)
local f_src_mac   = ProtoField.uint8("cdnet.src_mac", "Source MAC", base.HEX)
local f_dst_net   = ProtoField.uint8("cdnet.dst_net", "Destination Net", base.HEX)
local f_dst_mac   = ProtoField.uint8("cdnet.dst_mac", "Destination MAC", base.HEX)
local f_mcast     = ProtoField.uint16("cdnet.mcast_id", "Multicast ID", base.HEX)
local f_src_port  = ProtoField.uint16("cdnet.src_port", "Source Port", base.HEX)
local f_dst_port  = ProtoField.uint16("cdnet.dst_port", "Destination Port", base.HEX)
local f_src_addr  = ProtoField.string("cdnet.src", "Source Address")
local f_dst_addr  = ProtoField.string("cdnet.dst", "Destination Address")
local f_data      = ProtoField.bytes("cdnet.data", "Data")
local f_text      = ProtoField.string("cdnet.text", "Text")
local f_udp_sport = ProtoField.uint16("cdnet.udp_src_port", "UDP Source Port", base.DEC)
local f_udp_dport = ProtoField.uint16("cdnet.udp_dst_port", "UDP Destination Port", base.DEC)
local f_status    = ProtoField.uint8("cdnet.status", "Status", base.DEC, nil, 0x7f)
-- register access, port 5: [cmd, addr16, len8] to read, [cmd, addr16, data] to write
local f_reg_cmd   = ProtoField.uint8("cdnet.reg.cmd", "Command", base.HEX, VALS_REG_CMD)
local f_reg_addr  = ProtoField.uint16("cdnet.reg.addr", "Address", base.HEX)
local f_reg_len   = ProtoField.uint8("cdnet.reg.len", "Length", base.DEC)
-- flash access, port 8: [cmd, addr32, len8] to read, [cmd, addr32, data] to write,
-- [cmd, addr32, len32] to erase or to read a crc
local f_fl_cmd    = ProtoField.uint8("cdnet.flash.cmd", "Command", base.HEX, VALS_FLASH_CMD)
local f_fl_addr   = ProtoField.uint32("cdnet.flash.addr", "Address", base.HEX)
local f_fl_len    = ProtoField.uint32("cdnet.flash.len", "Length", base.DEC)
local f_fl_crc    = ProtoField.uint16("cdnet.flash.crc", "CRC", base.HEX)

p_cdnet.fields = { f_level, f_hdr, f_multi_net, f_multicast, f_reserved, f_src_p16, f_dst_p16,
                   f_src_net, f_src_mac, f_dst_net, f_dst_mac, f_mcast, f_src_port, f_dst_port,
                   f_src_addr, f_dst_addr, f_data, f_text, f_udp_sport, f_udp_dport, f_status,
                   f_reg_cmd, f_reg_addr, f_reg_len, f_fl_cmd, f_fl_addr, f_fl_len, f_fl_crc }

local e_short = ProtoExpert.new("cdnet.short", "Packet too short for its header",
                                expert.group.MALFORMED, expert.severity.ERROR)
local e_level = ProtoExpert.new("cdnet.level.bad", "Header bit 6 set: not a cdnet 2.1 packet",
                                expert.group.UNDECODED, expert.severity.WARN)
p_cdnet.experts = { e_short, e_level }


local function port_name(p)
    local name = PORT_NAMES[p]
    if name then
        return string.format("%s(%x)", name, p)
    end
    return string.format("p%x", p)
end

-- what the data means, by port: a request goes to the port, an answer comes from it
local function describe(t, tvb, off, src_port, dst_port)
    local n = tvb:len() - off
    local dat = n > 0 and tvb:raw(off, n) or ""
    local req = dst_port  -- the service a request addresses
    local ans = src_port  -- the service an answer comes from

    if req == 0x9 then -- debug print: the device's text
        t:add(f_text, tvb(off, n))
        return printable(dat)
    end
    if req == 0x1 then
        if n > 0 then t:add(f_data, tvb(off, n)) end
        return "device info?"
    end
    if ans == 0x1 then
        t:add(f_text, tvb(off, n))
        return printable(dat)
    end

    if req == 0x5 and n >= 3 then
        local cmd = tvb(off, 1):uint()
        local addr = tvb(off + 1, 2):le_uint()
        t:add(f_reg_cmd, tvb(off, 1))
        t:add_le(f_reg_addr, tvb(off + 1, 2))
        local name = VALS_REG_CMD[cmd] or string.format("cmd 0x%02x", cmd)
        if cmd == 0x00 and n >= 4 then
            t:add(f_reg_len, tvb(off + 3, 1))
            return string.format("%s 0x%04x, %d bytes", name, addr, tvb(off + 3, 1):uint())
        end
        if n > 3 then
            t:add(f_data, tvb(off + 3, n - 3))
        end
        return string.format("%s 0x%04x: %s", name, addr, hex_brief(dat:sub(4)))
    end

    if req == 0x8 and n >= 5 then
        local cmd = tvb(off, 1):uint()
        local addr = tvb(off + 1, 4):le_uint()
        t:add(f_fl_cmd, tvb(off, 1))
        t:add_le(f_fl_addr, tvb(off + 1, 4))
        local name = VALS_FLASH_CMD[cmd] or string.format("cmd 0x%02x", cmd)
        if cmd == 0x00 and n >= 6 then
            t:add(f_fl_len, tvb(off + 5, 1))
            return string.format("%s 0x%08x, %d bytes", name, addr, tvb(off + 5, 1):uint())
        end
        if (cmd == 0x2f or cmd == 0x10) and n >= 9 then
            t:add_le(f_fl_len, tvb(off + 5, 4))
            return string.format("%s 0x%08x, %d bytes", name, addr, tvb(off + 5, 4):le_uint())
        end
        if n > 5 then
            t:add(f_data, tvb(off + 5, n - 5))
        end
        return string.format("%s 0x%08x: %d bytes", name, addr, n - 5)
    end

    if (ans == 0x5 or ans == 0x8) and n >= 1 then
        local status = band(tvb(off, 1):uint(), 0x7f)
        t:add(f_status, tvb(off, 1))
        if n > 1 then
            t:add(f_data, tvb(off + 1, n - 1))
        end
        local s = status == 0 and "ok" or string.format("status %d", status)
        if ans == 0x8 and n == 3 and status == 0 then -- the crc read back
            t:add_le(f_fl_crc, tvb(off + 1, 2))
            return string.format("%s, crc 0x%04x", s, tvb(off + 1, 2):le_uint())
        end
        if n > 1 then
            return string.format("%s: %s", s, hex_brief(dat:sub(2)))
        end
        return s
    end

    if n > 0 then
        t:add(f_data, tvb(off, n))
        return string.format("%d bytes: %s", n, hex_brief(dat))
    end
    return "empty"
end

-- tvb is the payload; src_mac / dst_mac come from the cdbus header around it
local function dissect_cdnet(tvb, pinfo, tree, src_mac, dst_mac)
    local n = tvb:len()
    local t = tree:add(p_cdnet, tvb(), "CDNET")
    if n < 1 then
        t:add_proto_expert_info(e_short)
        return "empty payload"
    end
    local hdr = tvb(0, 1):uint()
    local local_net = p_cdnet.prefs.local_net
    local src, dst, src_port, dst_port, off

    t:add(f_level, tvb(0, 1))
    if band(hdr, 0x80) == 0 then
        -- level 0: [src_port, dst_port], bit 7 of each clear
        if n < 2 then
            t:add_proto_expert_info(e_short)
            return "short level 0 header"
        end
        src_port = band(hdr, 0x7f)
        dst_port = band(tvb(1, 1):uint(), 0x7f)
        t:add(f_src_port, tvb(0, 1), src_port)
        t:add(f_dst_port, tvb(1, 1), dst_port)
        src = string.format("00:%02x:%02x", local_net, src_mac)
        dst = string.format("00:%02x:%02x", local_net, dst_mac)
        off = 2
    else
        -- level 1: header byte, then the addresses the flags call for, then the ports
        local th = t:add(f_hdr, tvb(0, 1))
        th:add(f_multi_net, tvb(0, 1))
        th:add(f_multicast, tvb(0, 1))
        th:add(f_reserved, tvb(0, 1))
        th:add(f_src_p16, tvb(0, 1))
        th:add(f_dst_p16, tvb(0, 1))
        if band(hdr, 0x40) ~= 0 then
            t:add_proto_expert_info(e_level)
            if n > 1 then
                t:add(f_data, tvb(1, n - 1))
            end
            return string.format("header 0x%02x, not cdnet 2.1: %s", hdr, hex_brief(tvb:raw(0, n)))
        end
        local multi_net = band(hdr, 0x20) ~= 0
        local multicast = band(hdr, 0x10) ~= 0
        local need = 1 + (multi_net and 2 or 0) + ((multi_net or multicast) and 2 or 0)
                       + (band(hdr, 0x02) ~= 0 and 2 or 1) + (band(hdr, 0x01) ~= 0 and 2 or 1)
        if n < need then
            t:add_proto_expert_info(e_short)
            return string.format("short level 1 header, %d of %d bytes", n, need)
        end
        off = 1
        if multi_net then
            t:add(f_src_net, tvb(off, 1))
            t:add(f_src_mac, tvb(off + 1, 1))
            src = string.format("a0:%02x:%02x", tvb(off, 1):uint(), tvb(off + 1, 1):uint())
            off = off + 2
        else
            src = string.format("80:%02x:%02x", local_net, src_mac)
        end
        if multicast then
            t:add(f_mcast, tvb(off, 2))
            dst = string.format("%s:%02x:%02x", multi_net and "b0" or "90",
                                tvb(off, 1):uint(), tvb(off + 1, 1):uint())
            off = off + 2
        elseif multi_net then
            t:add(f_dst_net, tvb(off, 1))
            t:add(f_dst_mac, tvb(off + 1, 1))
            dst = string.format("a0:%02x:%02x", tvb(off, 1):uint(), tvb(off + 1, 1):uint())
            off = off + 2
        else
            dst = string.format("80:%02x:%02x", local_net, dst_mac)
        end
        if band(hdr, 0x02) ~= 0 then
            src_port = tvb(off, 2):le_uint()
            t:add_le(f_src_port, tvb(off, 2))
            off = off + 2
        else
            src_port = tvb(off, 1):uint()
            t:add(f_src_port, tvb(off, 1))
            off = off + 1
        end
        if band(hdr, 0x01) ~= 0 then
            dst_port = tvb(off, 2):le_uint()
            t:add_le(f_dst_port, tvb(off, 2))
            off = off + 2
        else
            dst_port = tvb(off, 1):uint()
            t:add(f_dst_port, tvb(off, 1))
            off = off + 1
        end
    end

    t:add(f_src_addr, tvb(0, 0), src):set_generated()
    t:add(f_dst_addr, tvb(0, 0), dst):set_generated()
    t:append_text(string.format(", %s:%x -> %s:%x", src, src_port, dst, dst_port))
    pinfo.cols.src = src
    pinfo.cols.dst = dst

    local what = describe(t, tvb, off, src_port, dst_port)
    return string.format("%s -> %s  %s", port_name(src_port), port_name(dst_port), what)
end


function p_cdbus.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "CDBUS"
    local n = tvb:len()
    local t = tree:add(p_cdbus, tvb(), "CDBUS")
    if n < 3 then
        t:add_proto_expert_info(e_len)
        pinfo.cols.info = string.format("short frame: %s", hex(tvb:raw(0, n)))
        return
    end
    local src, dst, len = tvb(0, 1):uint(), tvb(1, 1):uint(), tvb(2, 1):uint()
    t:add(f_src, tvb(0, 1))
    t:add(f_dst, tvb(1, 1))
    t:add(f_len, tvb(2, 1))
    t:append_text(string.format(", %02x -> %02x, %d bytes", src, dst, len))
    pinfo.cols.src = string.format("%02x", src)
    pinfo.cols.dst = string.format("%02x", dst)

    local info = ""
    if n ~= len + 3 and n ~= len + 5 then
        t:add_proto_expert_info(e_len)
        info = string.format("[length %d, expected %d] ", n, len + 5)
        if len > n - 3 then
            len = n - 3
        end
    elseif n == len + 5 then
        local ti = t:add_le(f_crc, tvb(len + 3, 2))
        local calc = modbus_crc(tvb:raw(0, len + 3))
        if calc == tvb(len + 3, 2):le_uint() then
            ti:append_text(" [correct]")
        else
            ti:append_text(string.format(" [wrong, should be 0x%04x]", calc))
            ti:add_proto_expert_info(e_crc)
            info = "[bad crc] "
        end
    end
    info = info .. dissect_cdnet(tvb(3, len):tvb(), pinfo, tree, src, dst)
    pinfo.cols.info = info
end


-- ---------------------------------------------------------------- cdnet over IPv6/UDP

local ipv6_src = Field.new("ipv6.src")
local ipv6_dst = Field.new("ipv6.dst")

-- the 16 bytes of an IPv6 address written out, nil when it is not one
local function ip6_bytes(s)
    s = s:gsub("/%d+$", "")
    local left, right = s:match("^(.-)::(.-)$")
    local function groups(part)
        local g = {}
        if part == "" then return g end
        for h in part:gmatch("[^:]+") do
            if not h:match("^%x%x?%x?%x?$") then return nil end
            g[#g + 1] = tonumber(h, 16)
        end
        return g
    end
    local l, r
    if left then
        l, r = groups(left), groups(right)
    else
        l, r = groups(s), {}
    end
    if not l or not r or #l + #r > 8 or (not left and #l ~= 8) then
        return nil
    end
    local words = {}
    for i = 1, 8 do words[i] = 0 end
    for i, v in ipairs(l) do words[i] = v end
    for i, v in ipairs(r) do words[8 - #r + i] = v end
    local t = {}
    for i = 1, 8 do
        t[#t + 1] = string.char(rshift(words[i], 8), band(words[i], 0xff))
    end
    return table.concat(t)
end

local prefix_cache = { text = nil, bytes = nil }

local function in_prefix(addr)
    local text = p_cdnet.prefs.prefix
    if prefix_cache.text ~= text then
        prefix_cache.text = text
        prefix_cache.bytes = ip6_bytes(text)
    end
    return prefix_cache.bytes ~= nil and addr:sub(1, 13) == prefix_cache.bytes:sub(1, 13)
end

-- the cdnet address an IPv6 address stands for: its last 3 bytes
local function ip6_cdnet(addr)
    return string.format("%02x:%02x:%02x", addr:byte(14), addr:byte(15), addr:byte(16))
end

-- a port of the host side carries the offset; a device port never does, so one at or above the
-- offset is the host's (a device port that high, 0xcdcd say, cannot be told apart from it)
local function udp_port(p)
    local offset = p_cdnet.prefs.port_offset
    if offset > 0 and p >= offset then
        return p - offset
    end
    return p
end

local function heur_udp(tvb, pinfo, tree)
    local fs, fd = ipv6_src(), ipv6_dst()
    if not fs or not fd then
        return false
    end
    local src_ip, dst_ip = fs.range:raw(), fd.range:raw()
    if not in_prefix(src_ip) and not in_prefix(dst_ip) then
        return false
    end
    pinfo.cols.protocol = "CDNET"
    local src, dst = ip6_cdnet(src_ip), ip6_cdnet(dst_ip)
    local src_port, dst_port = udp_port(pinfo.src_port), udp_port(pinfo.dst_port)
    local t = tree:add(p_cdnet, tvb(), "CDNET")
    t:append_text(string.format(" over UDP, %s:%x -> %s:%x", src, src_port, dst, dst_port))
    t:add(f_src_addr, tvb(0, 0), src):set_generated()
    t:add(f_dst_addr, tvb(0, 0), dst):set_generated()
    t:add(f_src_port, tvb(0, 0), src_port):set_generated()
    t:add(f_dst_port, tvb(0, 0), dst_port):set_generated()
    t:add(f_udp_sport, tvb(0, 0), pinfo.src_port):set_generated()
    t:add(f_udp_dport, tvb(0, 0), pinfo.dst_port):set_generated()
    local what = describe(t, tvb, 0, src_port, dst_port)
    pinfo.cols.info = string.format("%s:%s -> %s:%s  %s", src, port_name(src_port),
                                    dst, port_name(dst_port), what)
    return true
end

p_cdnet:register_heuristic("udp", heur_udp)


-- ---------------------------------------------------------------- marks

local p_mark = Proto("cdmark", "CDBUS GUI Mark")
local f_mark = ProtoField.string("cdmark.text", "Text")
p_mark.fields = { f_mark }

function p_mark.dissector(tvb, pinfo, tree)
    local n = tvb:len()
    local text = n > 0 and tvb:raw(0, n) or ""
    pinfo.cols.protocol = "MARK"
    pinfo.cols.src = "cdbus_gui"
    pinfo.cols.dst = ""
    local t = tree:add(p_mark, tvb(), "CDBUS GUI Mark: " .. printable(text))
    if n > 0 then
        t:add(f_mark, tvb(0, n))
    end
    pinfo.cols.info = "mark: " .. printable(text)
end


local wtap_encap = DissectorTable.get("wtap_encap")
wtap_encap:add(wtap.USER0, p_cdbus)
wtap_encap:add(wtap.USER1, p_mark)
