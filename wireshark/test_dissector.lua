-- Runs cdbus.lua against a stand-in for the parts of the Wireshark Lua API it uses, feeds it
-- frames and checks the columns and the tree. Wireshark itself is not needed:
--   lua wireshark/test_dissector.lua      (lua 5.2, 5.3 or 5.4; -v prints every tree)
--
-- The stand-in is strict where Wireshark is silent: a field added over a range of the wrong
-- size, or a range outside the buffer, is an error here, where Wireshark would show a wrong
-- value or stop dissecting.

local verbose = arg[1] == "-v"
local here = (arg[0]:match("^(.*)/[^/]*$") or ".")

-- ---------------------------------------------------------------- the stand-in

local SIZES = { uint8 = 1, uint16 = 2, uint32 = 4, bool = 1 }

ProtoField = {}
for _, ftype in ipairs({ "uint8", "uint16", "uint32", "bool", "string", "bytes" }) do
    ProtoField[ftype] = function(abbr, name, a, b, c)
        local f = { abbr = abbr, name = name, ftype = ftype, size = SIZES[ftype] }
        if ftype == "bool" then
            f.vals, f.mask = b, c
        elseif ftype:match("^uint") then
            f.base, f.vals, f.mask = a, b, c
        end
        return f
    end
end

base = { NONE = 0, DEC = 1, HEX = 2 }
expert = { group = { CHECKSUM = "checksum", MALFORMED = "malformed", UNDECODED = "undecoded" },
           severity = { NOTE = "note", WARN = "warn", ERROR = "error" } }
wtap = { USER0 = 147, USER1 = 148 }

ProtoExpert = { new = function(abbr, text, group, severity)
    return { abbr = abbr, text = text, group = group, severity = severity }
end }

Pref = { uint = function(label, default, descr) return default end,
         string = function(label, default, descr) return default end }

-- Field.new("ipv6.src") hands back whatever the test put in `fields_now` under that name
local fields_now = {}
Field = { new = function(name) return function() return fields_now[name] end end }

local protos = {}
local heuristics = {}
function Proto(name, desc)
    local p = { name = name, desc = desc, fields = {}, experts = {}, prefs = {},
                register_heuristic = function(self, lower, fn) heuristics[lower] = fn end }
    protos[name] = p
    return p
end

local tables = {}
DissectorTable = { get = function(name)
    tables[name] = tables[name] or { add = function(self, key, proto) self[key] = proto end }
    return tables[name]
end }

-- a buffer over a lua string; tvb(off, len) gives a range, tvb() the whole of it
local Tvb = {}
Tvb.__index = Tvb
local Range = {}
Range.__index = Range

local function new_tvb(s)
    return setmetatable({ s = s }, Tvb)
end
function Tvb:len() return #self.s end
function Tvb:raw(off, len)
    assert(off >= 0 and len >= 0 and off + len <= #self.s, "raw out of bounds")
    return self.s:sub(off + 1, off + len)
end
Tvb.__call = function(self, off, len)
    off = off or 0
    len = len or (#self.s - off)
    assert(off >= 0 and len >= 0 and off + len <= #self.s,
           string.format("range (%d, %d) out of a %d byte buffer", off, len, #self.s))
    return setmetatable({ buf = self, off = off, n = len }, Range)
end
function Range:len() return self.n end
function Range:raw() return self.buf.s:sub(self.off + 1, self.off + self.n) end
function Range:tvb() return new_tvb(self:raw()) end
function Range:uint()
    assert(self.n >= 1 and self.n <= 4, "uint of a bad length")
    local v = 0
    for i = 1, self.n do v = v * 256 + self:raw():byte(i) end
    return v
end
function Range:le_uint()
    assert(self.n >= 1 and self.n <= 4, "le_uint of a bad length")
    local v = 0
    for i = self.n, 1, -1 do v = v * 256 + self:raw():byte(i) end
    return v
end

-- the tree: every add() becomes a line, indented by depth
local Item = {}
Item.__index = Item

local function new_item(out, depth, text)
    local it = setmetatable({ out = out, depth = depth, idx = #out + 1 }, Item)
    out[it.idx] = string.rep("  ", depth) .. text
    return it
end

local function show(f, range, value, le)
    if f.ftype == "string" then
        return string.format("%s: %s", f.name, value or range:raw())
    elseif f.ftype == "bytes" then
        return string.format("%s: %s", f.name, (range:raw():gsub(".", function(c)
            return string.format("%02x", c:byte()) end)))
    end
    -- Wireshark reads as many bytes as the range has, up to the field's size (a 16 bit port
    -- over one byte is fine); with a value given the range is only what gets highlighted
    if value == nil then
        assert(range.n >= 1 and range.n <= f.size,
               string.format("%s: %d byte range for a %s", f.abbr, range.n, f.ftype))
    end
    assert(not le or f.size > 1, f.abbr .. ": add_le on a one byte field")
    local v = value or (le and range:le_uint() or range:uint())
    if f.mask then
        assert(not value, f.abbr .. ": value given for a masked field")
        local m, shift = f.mask, 0
        while m % 2 == 0 do m = m // 2; shift = shift + 1 end
        v = (v // (2 ^ shift)) % (m + 1)
        v = math.floor(v)
    end
    local s = tostring(v)
    if f.ftype == "bool" then
        s = v ~= 0 and "True" or "False"
    elseif f.base == base.HEX then
        s = string.format("0x%0" .. (f.size * 2) .. "x", v)
    end
    if f.vals and f.vals[v] then
        s = string.format("%s (%s)", f.vals[v], s)
    end
    return string.format("%s: %s", f.name, s)
end

function Item:add(f, range, value)
    if f.name and f.desc and f.prefs then -- a Proto
        return new_item(self.out, self.depth + 1, value or f.desc)
    end
    return new_item(self.out, self.depth + 1, show(f, range, value, false))
end
function Item:add_le(f, range)
    return new_item(self.out, self.depth + 1, show(f, range, nil, true))
end
function Item:append_text(s)
    self.out[self.idx] = self.out[self.idx] .. s
    return self
end
function Item:set_generated() return self end
function Item:add_proto_expert_info(e)
    new_item(self.out, self.depth + 1, string.format("[%s: %s]", e.severity, e.text))
    return self
end

local function new_pinfo(ports)
    local cols = {}
    local pinfo = { cols = setmetatable({}, { __newindex = cols, __index = cols }) }
    if ports then
        pinfo.src_port, pinfo.dst_port = ports[1], ports[2]
    end
    return pinfo, cols
end

-- ---------------------------------------------------------------- load the dissector

dofile(here .. "/cdbus.lua")
local cdbus = assert(tables.wtap_encap[147], "nothing registered for USER0")
local mark = assert(tables.wtap_encap[148], "nothing registered for USER1")
assert(cdbus.name == "cdbus" and mark.name == "cdmark")
local heur_udp = assert(heuristics.udp, "no udp heuristic registered")
assert(protos.cdnet.prefs.prefix == "fdcd::" and protos.cdnet.prefs.port_offset == 0xcd00)
assert(#protos.cdbus.fields == 4 and #protos.cdnet.fields > 20)

-- ---------------------------------------------------------------- helpers

local function crc16(s)
    local crc = 0xffff
    for i = 1, #s do
        crc = crc ~ s:byte(i)
        for _ = 1, 8 do
            if crc & 1 == 1 then crc = (crc >> 1) ~ 0xa001 else crc = crc >> 1 end
        end
    end
    return crc
end

local function bytes(...)
    return string.char(...)
end

-- a frame on the wire: src, dst, len, payload, crc
local function frame(src, dst, payload, no_crc)
    local f = bytes(src, dst, #payload) .. payload
    if no_crc then return f end
    local crc = crc16(f)
    return f .. bytes(crc % 256, crc // 256)
end

local function run(dissector, s)
    local out = {}
    local root = setmetatable({ out = out, depth = -1, idx = 0 }, Item)
    local pinfo, cols = new_pinfo(dissector.ports)
    if dissector.udp then -- a udp case: {udp = true, ips = {src, dst}, ports = {src, dst}}
        fields_now["ipv6.src"] = { range = new_tvb(dissector.ips[1])() }
        fields_now["ipv6.dst"] = { range = new_tvb(dissector.ips[2])() }
        cols.taken = heur_udp(new_tvb(s), pinfo, root)
    else
        dissector.dissector(new_tvb(s), pinfo, root)
    end
    return cols, out
end

local fails, count = 0, 0
local function check(name, dissector, s, want)
    count = count + 1
    local ok, cols, out = pcall(run, dissector, s)
    if not ok then
        fails = fails + 1
        print(string.format("FAIL %s: error: %s", name, cols))
        return
    end
    local bad = {}
    for k, v in pairs(want) do
        if k == "tree" then
            local tree = table.concat(out, "\n")
            for _, line in ipairs(v) do
                if not tree:find(line, 1, true) then
                    bad[#bad + 1] = string.format("tree lacks %q", line)
                end
            end
        elseif cols[k] ~= v then
            bad[#bad + 1] = string.format("%s = %q, want %q", k, tostring(cols[k]), v)
        end
    end
    if #bad > 0 then
        fails = fails + 1
        print("FAIL " .. name)
        for _, b in ipairs(bad) do print("  " .. b) end
        print("  tree:\n    " .. table.concat(out, "\n    "))
    elseif verbose then
        print("ok   " .. name)
        print("  " .. (cols.src or "") .. " -> " .. (cols.dst or "") .. "  " .. (cols.info or ""))
        print("    " .. table.concat(out, "\n    "))
    end
end

-- ---------------------------------------------------------------- the cases

-- level 0: [src_port, dst_port] data, addresses 00:net:mac
check("l0 dev info request", cdbus, frame(0x00, 0xfe, bytes(0x40, 0x01)),
      { protocol = "CDBUS", src = "00:00:00", dst = "00:00:fe", info = "p40 -> dev_info(1)  device info?",
        tree = { "CDBUS, 00 -> fe, 2 bytes", "CRC: 0x", "[correct]", "Level: Level 0 (0)",
                 "Source Port: 0x0040", "Destination Port: 0x0001",
                 "Source Address: 00:00:00", "Destination Address: 00:00:fe" } })

check("l0 dev info reply", cdbus, frame(0xfe, 0x00, bytes(0x01, 0x40) .. "cdfoc v3.1\n"),
      { src = "00:00:fe", dst = "00:00:00", info = "dev_info(1) -> p40  cdfoc v3.1",
        tree = { "Text: cdfoc v3.1\n" } })

-- level 1 local link: hdr 0x80, 1 byte ports
check("l1 reg read", cdbus, frame(0x00, 0x01, bytes(0x80, 0x40, 0x05, 0x00, 0x10, 0x00, 0x04)),
      { src = "80:00:00", dst = "80:00:01", info = "p40 -> reg(5)  read 0x0010, 4 bytes",
        tree = { "Level: Level 1 (1)", "Header: 0x80", "Multi Net: False", "Multicast: False",
                 "Source Port 16 bit: False", "Command: read (0x00)", "Address: 0x0010", "Length: 4" } })

check("l1 reg write", cdbus, frame(0x00, 0x01, bytes(0x80, 0x41, 0x05, 0x20, 0x34, 0x12, 0xaa, 0xbb)),
      { info = "p41 -> reg(5)  write 0x1234: aa bb", tree = { "Command: write (0x20)", "Data: aabb" } })

check("l1 reg write no reply", cdbus, frame(0x00, 0x01, bytes(0x80, 0x41, 0x05, 0xa0, 0x34, 0x12, 0x01)),
      { info = "p41 -> reg(5)  write, no reply 0x1234: 01" })

check("l1 reg reply ok with data", cdbus, frame(0x01, 0x00, bytes(0x80, 0x05, 0x40, 0x80, 1, 2, 3, 4)),
      { src = "80:00:01", dst = "80:00:00", info = "reg(5) -> p40  ok: 01 02 03 04",
        tree = { "Status: 0", "Data: 01020304" } })

check("l1 reg reply error", cdbus, frame(0x01, 0x00, bytes(0x80, 0x05, 0x40, 0x81)),
      { info = "reg(5) -> p40  status 1" })

-- 16 bit ports: hdr bit 1 (src) and bit 0 (dst), little endian
check("l1 16 bit ports", cdbus, frame(0x00, 0x01, bytes(0x83, 0xcd, 0xab, 0x34, 0x12, 0x99)),
      { info = "pabcd -> p1234  1 bytes: 99",
        tree = { "Source Port 16 bit: True", "Destination Port 16 bit: True",
                 "Source Port: 0xabcd", "Destination Port: 0x1234" } })

check("l1 16 bit dst port only", cdbus, frame(0x00, 0x01, bytes(0x81, 0x40, 0x34, 0x12)),
      { info = "p40 -> p1234  empty" })

-- multi net: hdr 0x20, [src_net, src_mac, dst_net, dst_mac], addresses a0:net:mac
check("l1 multi net", cdbus, frame(0x00, 0x01, bytes(0xa0, 0x01, 0x02, 0x03, 0x04, 0x40, 0x01)),
      { src = "a0:01:02", dst = "a0:03:04", info = "p40 -> dev_info(1)  device info?",
        tree = { "Multi Net: True", "Source Net: 0x01", "Source MAC: 0x02",
                 "Destination Net: 0x03", "Destination MAC: 0x04" } })

-- local multicast: hdr 0x10, [mh, ml], dst 90:mh:ml
check("l1 multicast", cdbus, frame(0x00, 0xff, bytes(0x90, 0x12, 0x34, 0x40, 0x09, 0x61)),
      { src = "80:00:00", dst = "90:12:34", info = "p40 -> dbg(9)  a",
        tree = { "Multicast: True", "Multicast ID: 0x1234" } })

-- cross net multicast: hdr 0x30, [src_net, src_mac, mh, ml], dst b0:mh:ml
check("l1 cross net multicast", cdbus, frame(0x00, 0xff, bytes(0xb0, 0x05, 0x06, 0x12, 0x34, 0x40, 0x09)),
      { src = "a0:05:06", dst = "b0:12:34", info = "p40 -> dbg(9)  " })

-- debug print: colour codes out of the Info column, line breaks shown, trailing one dropped
check("dbg text", cdbus, frame(0x01, 0x00, bytes(0x80, 0x09, 0x09) .. "12:00:00: \27[32mok\27[0m\nnext\n"),
      { info = "dbg(9) -> dbg(9)  12:00:00: ok | next", tree = { "Text: 12:00:00: " } })

-- flash: erase and the crc that comes back
check("flash erase", cdbus, frame(0x00, 0x01, bytes(0x80, 0x40, 0x08, 0x2f, 0x00, 0x80, 0x00, 0x08, 0x00, 0x10, 0x00, 0x00)),
      { info = "p40 -> flash(8)  erase 0x08008000, 4096 bytes",
        tree = { "Command: erase (0x2f)", "Address: 0x08008000", "Length: 4096" } })

check("flash read", cdbus, frame(0x00, 0x01, bytes(0x80, 0x40, 0x08, 0x00, 0x00, 0x80, 0x00, 0x08, 0x80)),
      { info = "p40 -> flash(8)  read 0x08008000, 128 bytes" })

check("flash write", cdbus, frame(0x00, 0x01, bytes(0x80, 0x40, 0x08, 0x20, 0x00, 0x80, 0x00, 0x08) .. string.rep("\1", 100)),
      { info = "p40 -> flash(8)  write 0x08008000: 100 bytes" })

check("flash crc reply", cdbus, frame(0x01, 0x00, bytes(0x80, 0x08, 0x40, 0x80, 0x34, 0x12)),
      { info = "flash(8) -> p40  ok, crc 0x1234", tree = { "CRC: 0x1234" } })

check("plot data", cdbus, frame(0x01, 0x00, bytes(0x80, 0x0a, 0x0a) .. string.rep("\7", 40)),
      { info = "plot(a) -> plot(a)  40 bytes: 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 ..." })

-- errors: bad crc, no crc, length byte off, too short, empty payload, header bit 6
local f = frame(0x00, 0xfe, bytes(0x40, 0x01))
check("bad crc", cdbus, f:sub(1, -2) .. "\0",
      { info = "[bad crc] p40 -> dev_info(1)  device info?", tree = { "[wrong, should be 0x", "[error: CRC does not match]" } })

check("no crc", cdbus, frame(0x00, 0xfe, bytes(0x40, 0x01), true),
      { info = "p40 -> dev_info(1)  device info?" })

check("length byte off", cdbus, bytes(0x00, 0xfe, 0x09, 0x40, 0x01),
      { info = "[length 5, expected 14] p40 -> dev_info(1)  device info?",
        tree = { "[error: Frame length does not match the length byte]" } })

check("too short", cdbus, bytes(0x00, 0xfe),
      { info = "short frame: 00 fe", tree = { "[error: Frame length does not match the length byte]" } })

check("empty frame", cdbus, "", { info = "short frame: " })

check("empty payload", cdbus, frame(0x00, 0xfe, ""),
      { info = "empty payload", tree = { "[error: Packet too short for its header]" } })

check("short l0", cdbus, frame(0x00, 0xfe, bytes(0x40)),
      { info = "short level 0 header" })

check("short l1", cdbus, frame(0x00, 0xfe, bytes(0xa0, 0x01, 0x02)),
      { info = "short level 1 header, 3 of 7 bytes" })

check("header bit 6", cdbus, frame(0x00, 0xfe, bytes(0xc0, 0x11, 0x22)),
      { info = "header 0xc0, not cdnet 2.1: c0 11 22", tree = { "[warn: Header bit 6 set" } })

-- the marks
check("mark", mark, "motor", { protocol = "MARK", src = "cdbus_gui", info = "mark: motor", tree = { "Text: motor" } })
check("empty mark", mark, "", { info = "mark: " })

-- cdnet over IPv6/UDP, a capture on tun0 or cdbus0: addresses from the IPv6 ones, ports from
-- UDP with the host's offset taken off, the payload is the data alone
-- addresses as cdnet_tun and the bridge use them, written out
local PFX = "\xfd\xcd" .. string.rep("\0", 11)             -- fdcd::/104, 13 bytes
local HOST_L1, HOST_L0 = PFX .. "\x80\x00\x00", PFX .. "\x00\x00\x00"
local DEV_FE = PFX .. "\x80\x00\xfe"
local BRIDGE = PFX .. "\x10\x00\x00"
local MCAST = PFX .. "\x90\x00\xff"
local OTHER = "\x20\x01\x0d\xb8" .. string.rep("\0", 11) .. "\x01"
local function udp(ips, ports) return { udp = true, ips = ips, ports = ports } end

check("udp reg read from the host", udp({ HOST_L1, DEV_FE }, { 0xcd40, 5 }), bytes(0x00, 0x10, 0x00, 0x04),
      { taken = true, protocol = "CDNET", info = "80:00:00:p40 -> 80:00:fe:reg(5)  read 0x0010, 4 bytes",
        tree = { "CDNET over UDP, 80:00:00:40 -> 80:00:fe:5", "Source Address: 80:00:00", "Destination Address: 80:00:fe",
                 "Source Port: 0x0040", "Destination Port: 0x0005", "UDP Source Port: 52544", "UDP Destination Port: 5",
                 "Command: read (0x00)", "Address: 0x0010" } })

check("udp reg reply to the host", udp({ DEV_FE, HOST_L1 }, { 5, 0xcd40 }), bytes(0x80, 1, 2, 3, 4),
      { taken = true, info = "80:00:fe:reg(5) -> 80:00:00:p40  ok: 01 02 03 04" })

check("udp dbg from the bridge itself", udp({ BRIDGE, HOST_L0 }, { 9, 0xcd09 }), "boot ok\n",
      { taken = true, info = "10:00:00:dbg(9) -> 00:00:00:dbg(9)  boot ok", tree = { "Text: boot ok" } })

check("udp multicast", udp({ HOST_L1, MCAST }, { 0xcd40, 0xcdcd }), bytes(1),
      { taken = true, info = "80:00:00:p40 -> 90:00:ff:pcd  1 bytes: 01" })

check("udp one side ours is enough", udp({ OTHER, HOST_L1 }, { 1234, 5 }), bytes(1),
      { taken = true, info = "00:00:01:p4d2 -> 80:00:00:reg(5)  1 bytes: 01" })
check("udp not ours either way", udp({ OTHER, OTHER }, { 0xcd40, 5 }), bytes(1), { taken = false })

protos.cdnet.prefs.port_offset = 0
check("udp offset off", udp({ HOST_L1, DEV_FE }, { 0xcd40, 5 }), bytes(0x00, 0x10, 0x00, 0x04),
      { info = "80:00:00:pcd40 -> 80:00:fe:reg(5)  read 0x0010, 4 bytes" })
protos.cdnet.prefs.port_offset = 0xcd00

protos.cdnet.prefs.prefix = "2001:db8::/104"
check("udp other prefix", udp({ OTHER, HOST_L1 }, { 0xcd40, 5 }), bytes(0x80),
      { taken = true, info = "00:00:01:p40 -> 80:00:00:reg(5)  1 bytes: 80" })
protos.cdnet.prefs.prefix = "fdcd::"
check("udp prefix back", udp({ OTHER, OTHER }, { 0xcd40, 5 }), bytes(0x80), { taken = false })
protos.cdnet.prefs.prefix = "not an address"
check("udp bad prefix takes nothing", udp({ HOST_L1, DEV_FE }, { 0xcd40, 5 }), bytes(0x80), { taken = false })
protos.cdnet.prefs.prefix = "fdcd::"

-- the local net preference
protos.cdnet.prefs.local_net = 0x12
check("local net pref", cdbus, frame(0x00, 0xfe, bytes(0x40, 0x01)), { src = "00:12:00", dst = "00:12:fe" })
check("local net pref l1", cdbus, frame(0x00, 0xfe, bytes(0x80, 0x40, 0x01)), { src = "80:12:00", dst = "80:12:fe" })

print(string.format("%d of %d dissector cases passed", count - fails, count))
os.exit(fails == 0 and 0 or 1)
