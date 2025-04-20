-- Plugin Information
local plugin_info = {
    version = "1.0.0",
    description = "DDoS Detector Plugin",
    author = "Harry Caldwell",
    repository = "https://github.com/harrycaldwell/Final-Project---DDoS-Detection"
}

-- Proto Declarations
SynFlood = Proto("SYNFlood", "SYN Flood Attack Detection")
UDPFlood = Proto("UDPFlood", "UDP Flood Attack Detection")
IMCPFlood = Proto("IMCPFlood", "ICMP Flood Attack Detection")

-- Make Proto objects globally accessible
_G["SynFlood"] = SynFlood
_G["UDPFlood"] = UDPFlood
_G["IMCPFlood"] = IMCPFlood

-- Configuration
local config = {
    default_threshold = 100, -- Default threshold for flood detection
    default_rate_threshold = 50, -- Default packets per second threshold
    default_port = 80,       -- Default port to monitor
}

-- State Variables
local threshold = config.default_threshold
local rate_threshold = config.default_rate_threshold
local port = config.default_port
local alert_triggered = {}
local dissector_states = {
    SYNFlood = false,
    UDPFlood = false,
    IMCPFlood = false
}

-- Packet Trackers
local syn_tracker = {}
local udp_tracker = {}
local icmp_tracker = {}
local packet_rate_tracker = {}
local alerted_ips = {}

-- Field Extractors
local tcp_flags_f = Field.new("tcp.flags")

-- Utility Functions
local function log_alert(protocol, key, count, tree, buffer)
    print(protocol .. " Flood detected: " .. key .. " (" .. count .. " packets)")
    local subtree = tree:add(_G[protocol], buffer(), protocol .. " Flood Detection")
    subtree:add(buffer(), protocol .. " Flood detected: " .. key)
    subtree:add(buffer(), protocol .. " packet count: " .. count)
    subtree:add(buffer(), "Threshold: " .. threshold)
end

local function trigger_alert(protocol, key, tracker, src_ip, tree, buffer)
    if not alerted_ips[src_ip] then
        print("IP " .. src_ip .. " has triggered an alert and is now logged.")
        if gui_enabled() then
            Create_popup(protocol .. " Flood detected: " .. key .. " (" .. tracker[key].count .. " packets)")
        end
        log_alert(protocol, key, tracker[key].count, tree, buffer)
        alerted_ips[src_ip] = true
        alert_triggered[key] = true
    end
end

local function track_packet(tracker, key)
    if not tracker[key] then
        tracker[key] = { count = 0, timestamp = os.time() }
    end
    tracker[key].count = tracker[key].count + 1
    tracker[key].timestamp = os.time()
end

local function track_packet_rate(tracker, key)
    local current_time = os.time()

    -- Initialize tracker for the key if it doesn't exist
    if not tracker[key] then
        tracker[key] = { timestamps = {}, count = 0 }
    end

    -- Add the current timestamp to the list
    table.insert(tracker[key].timestamps, current_time)
    tracker[key].count = tracker[key].count + 1

    -- Remove timestamps older than 1 second
    while #tracker[key].timestamps > 0 and current_time - tracker[key].timestamps[1] > 1 do
        table.remove(tracker[key].timestamps, 1)
    end

    -- Calculate the packet rate
    local packet_rate = #tracker[key].timestamps

    -- Check if the rate exceeds the threshold
    if packet_rate >= rate_threshold then
        print("High packet rate detected for " .. key .. ": " .. packet_rate .. " packets/second")
        trigger_alert("HighRate", key, tracker, key, nil, nil) -- Trigger alert
    end
end

local function detect_flood(protocol, tracker, key, src_ip, tree, buffer)
    if tracker[key].count >= threshold then
        trigger_alert(protocol, key, tracker, src_ip, tree, buffer)
        Cleanup_tables()
    end
end

-- Cleanup Function
function Cleanup_tables()
    local trackers = { syn_tracker, udp_tracker, icmp_tracker, packet_rate_tracker }
    for _, tracker in ipairs(trackers) do
        for key in pairs(tracker) do
            tracker[key] = nil
        end
    end
    for key in pairs(alert_triggered) do
        alert_triggered[key] = nil
    end
    print("All trackers and alerts have been cleared.")
end

-- GUI Helper Function
function Create_popup(message)
    os.execute("zenity --info --text='" .. message .. "'")
end

-- User Configuration Functions
function Set_port(new_port)
    if type(new_port) == "number" and new_port >= 0 then
        port = new_port
        print("Port changed to: " .. port)
    else
        print("Invalid Port Number. Please use a non-negative number.")
    end
end

function Set_threshold(new_threshold)
    if type(new_threshold) == "number" and new_threshold >= 0 then
        threshold = new_threshold
        print("Threshold set to: " .. threshold)
    else
        print("Invalid Threshold Value. Please use a non-negative number.")
    end
end

function Set_rate_threshold(new_rate_threshold)
    if type(new_rate_threshold) == "number" and new_rate_threshold >= 0 then
        rate_threshold = new_rate_threshold
        print("Rate threshold set to: " .. rate_threshold)
    else
        print("Invalid Rate Threshold Value. Please use a non-negative number.")
    end
end

-- Menu Actions
local function threshold_action()
    local handle = io.popen("zenity --entry --title='Set Threshold' --text='Enter the threshold value:'")
    if handle then
        local input = handle:read("*a")
        handle:close()
        input = input and input:match("^%s*(.-)%s*$") or ""

        if input == "" then
            Create_popup("Threshold update canceled.")
            return
        end

        local new_threshold = tonumber(input)
        if new_threshold then
            Set_threshold(new_threshold)
        else
            Create_popup("Invalid Threshold Value. Please use a non-negative number.")
        end
    else
        Create_popup("Failed to open input prompt.")
    end
end

local function port_action()
    local handle = io.popen("zenity --entry --title='Set Port' --text='Enter the port number:'")
    if handle then
        local input = handle:read("*a")
        handle:close()
        input = input and input:match("^%s*(.-)%s*$") or ""

        if input == "" then
            Create_popup("Port update canceled.")
            return
        end

        local new_port = tonumber(input)
        if new_port then
            Set_port(new_port)
        else
            Create_popup("Invalid Port Number. Please use a non-negative number.")
        end
    else
        Create_popup("Failed to open input prompt.")
    end
end

function toggle_dissector(dissector_name)
    if dissector_states[dissector_name] ~= nil then
        dissector_states[dissector_name] = not dissector_states[dissector_name]
        print(dissector_name .. " is now " .. (dissector_states[dissector_name] and "enabled" or "disabled"))
    else
        print("Invalid dissector name: " .. dissector_name)
    end
end

-- SYN Flood Detection
function SynFlood.dissector(buffer, pinfo, tree)
    if not dissector_states["SYNFlood"] then return end

    local tcp_flags_field = tcp_flags_f()
    if not tcp_flags_field then return end

    local tcp_flags = tonumber(tostring(tcp_flags_field))
    if bit.band(tcp_flags, 0x02) == 0 then return end -- Skip if SYN flag is not set

    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)
    local dst_port = tostring(pinfo.dst_port)
    local key = src_ip .. "->" .. dst_ip .. ":" .. dst_port

    track_packet(syn_tracker, key)
    track_packet_rate(packet_rate_tracker, key)
    detect_flood("SYNFlood", syn_tracker, key, src_ip, tree, buffer)
end

-- UDP Flood Detection
function UDPFlood.dissector(buffer, pinfo, tree)
    if not dissector_states["UDPFlood"] then return end
    if not pinfo.cols.protocol or pinfo.cols.protocol ~= "UDP" then return end

    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)
    local dst_port = tostring(pinfo.dst_port)
    local key = src_ip .. "->" .. dst_ip .. ":" .. dst_port

    track_packet(udp_tracker, key)
    track_packet_rate(packet_rate_tracker, key)
    detect_flood("UDPFlood", udp_tracker, key, src_ip, tree, buffer)
end

-- ICMP Flood Detection (Placeholder)
function IMCPFlood.dissector(buffer, pinfo, tree)
    if not dissector_states["IMCPFlood"] then return end
    -- Add ICMP flood detection logic here
end

-- Register Dissectors
local function register_dissector(proto_name)
    local success, err = pcall(function()
        if not _G[proto_name] then
            error("Proto object '" .. proto_name .. "' is not defined or not globally accessible.")
        end
        register_postdissector(_G[proto_name])
        print(proto_name .. " dissector registered successfully")
    end)
    if not success then
        print("Failed to register " .. proto_name .. " dissector: " .. err)
    end
end

-- Registering Dissectors
register_dissector("SynFlood")
register_dissector("UDPFlood")
register_dissector("IMCPFlood")

-- GUI Menu Registration
local function register_menu_actions()
    register_menu("DDoS Detection/Set Threshold", threshold_action, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/Set Rate Threshold", function()
        local handle = io.popen("zenity --entry --title='Set Rate Threshold' --text='Enter the rate threshold (packets/second):'")
        if handle then
            local input = handle:read("*a")
            handle:close()
            input = input and input:match("^%s*(.-)%s*$") or ""

            if input == "" then
                Create_popup("Rate threshold update canceled.")
                return
            end

            local new_rate_threshold = tonumber(input)
            if new_rate_threshold then
                Set_rate_threshold(new_rate_threshold)
            else
                Create_popup("Invalid Rate Threshold Value. Please use a non-negative number.")
            end
        else
            Create_popup("Failed to open input prompt.")
        end
    end, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/Set Port", port_action, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/Toggle SYN Flood Detection", function() toggle_dissector("SYNFlood") end, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/Toggle UDP Flood Detection", function() toggle_dissector("UDPFlood") end, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/Toggle ICMP Flood Detection", function() toggle_dissector("IMCPFlood") end, MENU_TOOLS_UNSORTED)
end

-- Register GUI Menu Actions
register_menu_actions()