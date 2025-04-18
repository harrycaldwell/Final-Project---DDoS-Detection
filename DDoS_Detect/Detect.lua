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

-- Variable Declarations
local threshold = 0
local port = 80
local ttl = 60 -- Time to live for the packets when tracking (in seconds)
local last_alert_time = 0
local alert_interval = 10 -- Time interval for alerting (in seconds)
local alert_triggered = {}

local dissector_states = {
    SYNFlood = false,
    UDPFlood = false,
    IMCPFlood = false
}

-- Tables for tracking packets
local syn_tracker = {}
local udp_tracker = {}
local icmp_tracker = {}

-- Field Extractors
local tcp_flags_f = Field.new("tcp.flags")

-- Functions to create Pop-up windows
function Create_popup(message)
    local current_time = os.time()
    if current_time - last_alert_time >= alert_interval then
    os.execute("zenity --info --text='" .. message .. "'")
        last_alert_time = current_time
    else
        print("[ALERT SKIPPED]" .. message)
    end
end

-- Function that allows user to set port
function Set_port(new_port)
    if type(new_port) == "number" and new_port >= 0 then
        port = new_port
        print("Port changed to: " .. port)
    else
        print("Invalid Port Number. Please use a non-negative number.")
    end
end

-- Function to set the threshold value
function Set_threshold(new_threshold)
    if type(new_threshold) == "number" and new_threshold >= 0 then
        threshold = new_threshold
        print("Threshold set to: " .. threshold)
    else
        print("Invalid Threshold Value. Please use a non-negative number.")
    end
end

function Cleanup()
    local current_time = os.time()

    local function cleanup_tracker(tracker)   
    for key, count in pairs(tracker) do
        if current_time - count.timestamp > ttl then
            tracker[key] = nil
            alert_triggered[key] = nil
            print("Removed old entry: " .. key)
        end
    end
end

-- cleaning up the trackers
    cleanup_tracker(syn_tracker)
    cleanup_tracker(udp_tracker)
    cleanup_tracker(icmp_tracker)
end

-- Menu actions
-- Function for setting the threshold
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

-- Function for setting the port
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

-- Function to enable/disable the dissectors
function toggle_dissector(dissector_name)
    if dissector_states[dissector_name] ~= nil then
        dissector_states[dissector_name] = not dissector_states[dissector_name]
        print(dissector_name .. " is now " .. (dissector_states[dissector_name] and "enabled" or "disabled"))
    else
        print("Invalid dissector name: " .. dissector_name)
    end
end

-- GUI Menu register
if gui_enabled() then
    register_menu("DDoS Detection/Settings/Set Threshold", threshold_action, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/Settings/Set Port", port_action, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/Detection/SYN Flood/Enable-Disable", function() toggle_dissector("SYNFlood") end, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/Detection/UDP Flood/Enable-Disable", function() toggle_dissector("UDPFlood") end, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/Detection/ICMP Flood/Enable-Disable", function() toggle_dissector("IMCPFlood") end, MENU_TOOLS_UNSORTED)
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
    -- DEBUG :print(syn_tracker[key].count)
    -- DEBUG :print(syn_tracker[key])

    -- Trigger detection
    if syn_tracker[key].count >= threshold then
        if gui_enabled() then
            Create_popup("SYN Flood detected: " .. key .. " (" .. syn_tracker[key] .. " SYN packets)")
        end
        print("SYN Flood detected: " .. key .. " (" .. syn_tracker[key].count .. " SYN packets)")

        local subtree = tree:add(SynFlood, buffer(), "SYN Flood Detection")
        subtree:add(buffer(), "SYN Flood detected: " .. key)
        subtree:add(buffer(), "SYN packet count: " .. syn_tracker[key])
        subtree:add(buffer(), "Threshold: " .. threshold)

        -- Marks the alert as triggered for the key
        alert_triggered[key] = true
    end

    -- Cleanup old entries
    Cleanup()
end

-- Placeholder UDP and ICMP Flood Detection
function UDPFlood.dissector(buffer, pinfo, tree)
    if not dissector_states["UDPFlood"] then return end
    -- Add UDP flood detection logic here
    
    if not pinfo.cols.protocol or pinfo.cols.protocol == "UDP" then
        return
    end

    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)
    local dst_port = tostring(pinfo.dst_port)
    local key = src_ip .. "->" .. dst_ip .. ":" .. dst_port

    -- Counting UDP packets
    if not udp_tracker[key] then
        udp_tracker[key] = {count = 0, timestamp = os.time()}
    end
    udp_tracker[key].count = udp_tracker[key].count + 1
    udp_tracker[key].timestamp = os.time()
    -- DEBUG :print(udp_tracker[key])

    -- Trigger detection
    if udp_tracker[key].count >= threshold then
        if gui_enabled() then
            Create_popup("UDP Flood detected: " .. key .. " (" .. udp_tracker[key].count .. " UDP packets)")
        end
        print("UDP Flood detected: " .. key .. " (" .. udp_tracker[key].count .. " UDP packets)")

        local subtree = tree:add(UDPFlood, buffer(), "UDP Flood Detection")
        subtree:add(buffer(), "UDP Flood detected: " .. key)
        subtree:add(buffer(), "UDP packet count: " .. udp_tracker[key])
        subtree:add(buffer(), "Threshold: " .. threshold)

         -- Marks the alert as triggered for the key
         alert_triggered[key] = true
    end

    Cleanup()
end

function IMCPFlood.dissector(buffer, pinfo, tree)
    if not dissector_states["IMCPFlood"] then return end
    -- Add ICMP flood detection logic here
end

-- Registering of the dissectors
local success = pcall(function()
    register_postdissector(SynFlood)
    print("SYN Flood dissector registered successfully")
end)
if not success then
    print("Failed to register SYN Flood dissector")
end

success = pcall(function()
    register_postdissector(UDPFlood)
    print("UDP Flood dissector registered successfully")
end)
if not success then
    print("Failed to register UDP Flood dissector")
end

success = pcall(function()
    register_postdissector(IMCPFlood)
    print("ICMP Flood dissector registered successfully")
end)
if not success then
    print("Failed to register ICMP Flood dissector")
end
