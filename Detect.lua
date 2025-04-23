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
    default_port = 80,       -- Default port to monitor
}

-- State Variables
local threshold = config.default_threshold
local port = config.default_port
local alert_triggered = {}
local dissector_states = {
    SYNFlood = false,
    UDPFlood = false,
    IMCPFlood = false
}

local syn_rate_threshold = 10000 -- Packets per second for SYN flood detection
local udp_rate_threshold = 1000 -- Packets per second for UDP flood detection
local icmp_rate_threshold = 200 -- Packets per second for ICMP flood detection

-- Packet Trackers
local trackers = {
    SYNFlood = {},
    UDPFlood = {},
    IMCPFlood = {},
    packet_rate = {}
}
local alerted_ips = {}

-- Field Extractors
local tcp_flags_f = Field.new("tcp.flags")

-- Cleanup Function
local function cleanup_tables()
    -- Clear all trackers
    print("calling cleanup")
    for tracker_name, tracker in pairs(trackers) do
        if tracker then
            print("Clearing tracker: " .. tracker_name)
            for key in pairs(tracker) do
                print("Removing key: " .. key .. " from tracker: " .. tracker_name)
                tracker[key] = nil
            end
        end
    end

    -- Clear alert_triggered table
    print("Clearing alert_triggered table")
    for key in pairs(alert_triggered) do
        print("Removing alert key: " .. key)
        alert_triggered[key] = nil
    end

    print("All trackers and alerts have been cleared.")
end

-- Utility Functions
local function log_alert(protocol, key, count, tree, buffer)
    print(protocol .. " Flood detected: " .. key .. " (" .. count .. " packets)")
    local subtree = tree:add(_G[protocol], buffer(), protocol .. " Flood Detection")
    subtree:add(buffer(), protocol .. " Flood detected: " .. key)
    subtree:add(buffer(), protocol .. " packet count: " .. count)
    subtree:add(buffer(), "Threshold: " .. rate_threshold .. " packets/second")
end

local function trigger_alert(protocol, key, tracker, src_ip, tree, buffer)
    -- Check if the src_ip is already in the alerted_ips table
    if alerted_ips[src_ip] then
        print("IP " .. src_ip .. " is already in alerted_ips. Skipping alert.")
        return -- Exit the function if the IP is already alerted
    end

    -- Add the src_ip to the alerted_ips table
    print("IP " .. src_ip .. " has triggered an alert and is now logged.")
    alerted_ips[src_ip] = true -- Add the IP to the table

    -- Log the alert and handle GUI notifications
    if gui_enabled() then
        Create_popup(protocol .. " Flood detected: " .. key .. " (" .. tracker[key].count .. " packets)")
    end
    log_alert(protocol, key, tracker[key].count, tree, buffer)

    -- Mark the alert as triggered
    alert_triggered[key] = true

    -- Clear only the specific key from the tracker
    print("Clearing tracker data for key: " .. key)
    tracker[key] = nil
end

local function track_packet(tracker, key)
    if not tracker[key] then
        tracker[key] = { count = 0, timestamp = os.time() }
    end
    tracker[key].count = tracker[key].count + 1
    tracker[key].timestamp = os.time()
end

local function track_packet_rate(tracker, key, rate_threshold)
    local current_time = os.time()

    -- Initialize tracker for the key if it doesn't exist
    if not tracker[key] then
        tracker[key] = { timestamps = {}, count = 0 }
    end

    -- Add the current timestamp to the list
    table.insert(tracker[key].timestamps, current_time)
    tracker[key].count = tracker[key].count + 1

    --print("Current packet rate for " .. key .. ": " .. #tracker[key].timestamps .. " packets/second")

    -- Remove timestamps older than 1 second
    while #tracker[key].timestamps > 0 and current_time - tracker[key].timestamps[1] > 1 do
        table.remove(tracker[key].timestamps, 1)
    end

    -- Calculate the packet rate
    local packet_rate = #tracker[key].timestamps

    -- Check if the rate exceeds the threshold
    if packet_rate >= rate_threshold then
        --print("High packet rate detected for " .. key .. ": " .. packet_rate .. " packets/second")
        trigger_alert("High Rate", key, tracker, key, nil, nil) -- Trigger alert
    end
end

local function toggle_dissector(dissector_name)
    if dissector_states[dissector_name] ~= nil then
        dissector_states[dissector_name] = not dissector_states[dissector_name]
        print(dissector_name .. " is now " .. (dissector_states[dissector_name] and "enabled" or "disabled"))
    else
        print("Invalid dissector name: " .. dissector_name)
    end
end

local function detect_flood(protocol, tracker, key, src_ip, tree, buffer, rate_threshold)
    track_packet(tracker, key)
    track_packet_rate(trackers.packet_rate, key, rate_threshold)
end

-- Reusable Dissector Function
local function generic_dissector(protocol, tracker, pinfo, tree, buffer, rate_threshold, filter_function)
    if not dissector_states[protocol] then return end
    if filter_function and not filter_function(pinfo) then return end

    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)
    local dst_port = tonumber(pinfo.dst_port)
    local key = src_ip .. "->" .. dst_ip .. ":" .. dst_port

    -- port filtering
    if port ~= 0 and dst_port ~= port then
        return -- Skip packets that don't match the specified port
    end

    detect_flood(protocol, tracker, key, src_ip, tree, buffer, rate_threshold)
end

-- SYN Flood Detection
function SynFlood.dissector(buffer, pinfo, tree)
    generic_dissector("SYNFlood", trackers.SYNFlood, pinfo, tree, buffer, syn_rate_threshold, function(pinfo)
        local tcp_flags_field = tcp_flags_f()
        if not tcp_flags_field then return false end
        local tcp_flags = tonumber(tostring(tcp_flags_field))
        return bit.band(tcp_flags, 0x02) ~= 0 -- Only process packets with the SYN flag set
    end)

end

-- UDP Flood Detection
function UDPFlood.dissector(buffer, pinfo, tree)
    generic_dissector("UDPFlood", trackers.UDPFlood, pinfo, tree, buffer, udp_rate_threshold)
end

-- ICMP Flood Detection
function IMCPFlood.dissector(buffer, pinfo, tree)
    generic_dissector("IMCPFlood", trackers.IMCPFlood, pinfo, tree, buffer, icmp_rate_threshold, function(pinfo)
        return pinfo.cols.protocol == "ICMP"
    end)
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
    register_menu("DDoS Detection/Set Port", function()
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
    end, MENU_TOOLS_UNSORTED)

    register_menu("DDoS Detection/SYN Flood/Toggle", function() toggle_dissector("SYNFlood") end, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/SYN Flood/Set Rate Threshold", function()
        local handle = io.popen("zenity --entry --title='Set SYN Rate Threshold' --text='Enter the rate threshold (packets/second):'")
        if handle then
            local input = handle:read("*a")
            handle:close()
            input = input and input:match("^%s*(.-)%s*$") or ""

            if input == "" then
                Create_popup("SYN rate threshold update canceled.")
                return
            end

            local new_rate_threshold = tonumber(input)
            if new_rate_threshold then
                syn_rate_threshold = new_rate_threshold
                print("SYN rate threshold set to: " .. syn_rate_threshold)
            else
                Create_popup("Invalid SYN Rate Threshold Value. Please use a non-negative number.")
            end
        else
            Create_popup("Failed to open input prompt.")
        end
    end, MENU_TOOLS_UNSORTED)

    register_menu("DDoS Detection/UDP Flood/Toggle", function() toggle_dissector("UDPFlood") end, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/UDP Flood/Set Rate Threshold", function()
        local handle = io.popen("zenity --entry --title='Set UDP Rate Threshold' --text='Enter the rate threshold (packets/second):'")
        if handle then
            local input = handle:read("*a")
            handle:close()
            input = input and input:match("^%s*(.-)%s*$") or ""

            if input == "" then
                Create_popup("UDP rate threshold update canceled.")
                return
            end

            local new_rate_threshold = tonumber(input)
            if new_rate_threshold then
                udp_rate_threshold = new_rate_threshold
                print("UDP rate threshold set to: " .. udp_rate_threshold)
            else
                Create_popup("Invalid UDP Rate Threshold Value. Please use a non-negative number.")
            end
        else
            Create_popup("Failed to open input prompt.")
        end
    end, MENU_TOOLS_UNSORTED)

    register_menu("DDoS Detection/ICMP Flood/Toggle", function() toggle_dissector("IMCPFlood") end, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/ICMP Flood/Set Rate Threshold", function()
        local handle = io.popen("zenity --entry --title='Set ICMP Rate Threshold' --text='Enter the rate threshold (packets/second):'")
        if handle then
            local input = handle:read("*a")
            handle:close()
            input = input and input:match("^%s*(.-)%s*$") or ""

            if input == "" then
                Create_popup("ICMP rate threshold update canceled.")
                return
            end

            local new_rate_threshold = tonumber(input)
            if new_rate_threshold then
                icmp_rate_threshold = new_rate_threshold
                print("ICMP rate threshold set to: " .. icmp_rate_threshold)
            else
                Create_popup("Invalid ICMP Rate Threshold Value. Please use a non-negative number.")
            end
        else
            Create_popup("Failed to open input prompt.")
        end
    end, MENU_TOOLS_UNSORTED)

end

-- Register GUI Menu Actions
register_menu_actions()