-- Plugin Information
local plugin_info = {
    version = "1.0.0",
    description = "DDoS Detector Plugin",
    author = "Harry Caldwell",
    repository = "https://github.com/harrycaldwell/Final-Project---DDoS-Detection"
}

-- Proto Declarations
local SynFlood = Proto("SYNFlood", "SYN Flood Attack Detection")
local UDPFlood = Proto("UDPFlood", "UDP Flood Attack Detection")
local IMCPFlood = Proto("IMCPFlood", "ICMP Flood Attack Detection")

-- Constants
local DEFAULT_THRESHOLD = 10
local DEFAULT_PORT = 80

-- Variable Declarations
local threshold = DEFAULT_THRESHOLD
local port = DEFAULT_PORT
local alert_triggered = {}
local alerted_ips = {}
local syn_tracker = {}
local udp_tracker = {}
local icmp_tracker = {}
local debug_mode = true -- Enable or disable debug prints

-- Field Extractors
local tcp_flags_f = Field.new("tcp.flags")

-- Debug Print Function
local function debug_print(message)
    if debug_mode then
        print("[DEBUG] " .. message)
    end
end

-- Helper Function: Create Alerts
local function create_alert(message)
    if gui_enabled() then
        os.execute("zenity --info --text='" .. message .. "'")
    else
        print(message)
    end
end

-- Helper Function: Add Subtree Details
local function add_subtree_details(subtree, key, count, threshold)
    subtree:add("SYN Flood detected: " .. key)
    subtree:add("SYN packet count: " .. count)
    subtree:add("Threshold: " .. threshold)
end

-- Cleanup Function
local function cleanup_tables()
    for key in pairs(syn_tracker) do
        syn_tracker[key] = nil
    end
    for key in pairs(udp_tracker) do
        udp_tracker[key] = nil
    end
    for key in pairs(icmp_tracker) do
        icmp_tracker[key] = nil
    end
    for key in pairs(alert_triggered) do
        alert_triggered[key] = nil
    end
    print("All trackers and alerts have been cleared.")
end

-- SYN Flood Detection
function SynFlood.dissector(buffer, pinfo, tree)
    if not dissector_states["SYNFlood"] then return end

    -- Check if the packet is TCP
    local tcp_flags_field = tcp_flags_f()
    if not tcp_flags_field then return end

    local tcp_flags = tonumber(tostring(tcp_flags_field))
    if bit.band(tcp_flags, 0x02) == 0 then
        return -- Skip if SYN flag is not set
    end

    -- Extract IP and port
    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)
    local dst_port = tostring(pinfo.dst_port)
    local key = src_ip .. "->" .. dst_ip .. ":" .. dst_port

    -- Count SYN packets
    if not syn_tracker[key] then
        syn_tracker[key] = { count = 0, timestamp = os.time() }
    end
    syn_tracker[key].count = syn_tracker[key].count + 1
    syn_tracker[key].timestamp = os.time()

    -- Trigger detection
    if syn_tracker[key].count >= threshold then
        if not alerted_ips[src_ip] then
            alerted_ips[src_ip] = true
            create_alert("SYN Flood detected: " .. key .. " (" .. syn_tracker[key].count .. " SYN packets)")
            debug_print("IP " .. src_ip .. " has triggered an alert.")

            -- Add subtree details
            local subtree = tree:add(SynFlood, buffer(), "SYN Flood Detection")
            add_subtree_details(subtree, key, syn_tracker[key].count, threshold)

            -- Mark the alert as triggered
            alert_triggered[key] = true
        end

        -- Cleanup old entries
        cleanup_tables()
    end
end

-- Placeholder UDP Flood Detection
function UDPFlood.dissector(buffer, pinfo, tree)
    if not dissector_states["UDPFlood"] then return end

    -- Ensure the packet is UDP
    if not pinfo.cols.protocol or pinfo.cols.protocol ~= "UDP" then
        return
    end

    -- Extract IP and port
    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)
    local dst_port = tostring(pinfo.dst_port)
    local key = src_ip .. "->" .. dst_ip .. ":" .. dst_port

    -- Count UDP packets
    if not udp_tracker[key] then
        udp_tracker[key] = { count = 0, timestamp = os.time() }
    end
    udp_tracker[key].count = udp_tracker[key].count + 1
    udp_tracker[key].timestamp = os.time()

    -- Trigger detection
    if udp_tracker[key].count >= threshold then
        if not alerted_ips[src_ip] then
            alerted_ips[src_ip] = true
            create_alert("UDP Flood detected: " .. key .. " (" .. udp_tracker[key].count .. " UDP packets)")
            debug_print("IP " .. src_ip .. " has triggered a UDP Flood alert.")

            -- Add subtree details
            local subtree = tree:add(UDPFlood, buffer(), "UDP Flood Detection")
            add_subtree_details(subtree, key, udp_tracker[key].count, threshold)

            -- Mark the alert as triggered
            alert_triggered[key] = true
        end

        -- Cleanup old entries
        cleanup_tables()
    end
end

-- ICMP Flood Detection (Placeholder)
function IMCPFlood.dissector(buffer, pinfo, tree)
    if not dissector_states["IMCPFlood"] then return end
    -- Add ICMP flood detection logic here
end

-- Register Dissectors
local function register_dissector(proto, name)
    local success = pcall(function()
        register_postdissector(proto)
        print(name .. " dissector registered successfully")
    end)
    if not success then
        print("Failed to register " .. name .. " dissector")
    end
end

register_dissector(SynFlood, "SYN Flood")
register_dissector(UDPFlood, "UDP Flood")
register_dissector(IMCPFlood, "ICMP Flood")
