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
    os.execute("zenity --info --text='" .. message .. "'")
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

-- Menu actions
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
    local key = dst_ip .. ":" .. dst_port

    -- Count SYN packets
    syn_tracker[key] = (syn_tracker[key] or 0) + 1
    -- DEBUG :print(syn_tracker[key])

    -- Trigger detection
    if syn_tracker[key] >= threshold then
        if gui_enabled() then
            Create_popup("SYN Flood detected: " .. key .. " (" .. syn_tracker[key] .. " SYN packets)")
        end
        print("SYN Flood detected: " .. key .. " (" .. syn_tracker[key] .. " SYN packets)")

        local subtree = tree:add(SynFlood, buffer(), "SYN Flood Detection")
        subtree:add(buffer(), "SYN Flood detected: " .. key)
        subtree:add(buffer(), "SYN packet count: " .. syn_tracker[key])
        subtree:add(buffer(), "Threshold: " .. threshold)
    end
end

-- Placeholder UDP and ICMP Flood Detection
function UDPFlood.dissector(buffer, pinfo, tree)
    if not dissector_states["UDPFlood"] then return end
    -- Add UDP flood detection logic here
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
