local plugin_info = {
    version = "1.0.0",
    description = "DDoS Detector Plugin",
    author = "Harry Caldwell",
    repository = "https://github.com/harrycaldwell/Final-Project---DDoS-Detection"
}

-- Proto Declarations
local SynFlood = Proto("SYNFlood", "SYN Flood Attack Detection")

-- Variable Declarations
local threshold = 0
local port = 80

--Functionality for the GUI stuff
-- Functions to create Pop-up windows
function Create_popup(message)
    os.execute("zenity --info --text='" .. message .. "'")
end

-- Alert Functions
function Alert()
    -- TODO: Implement alert functionality
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
-- Menu action for setting the threshold
local function threshold_action()
    local handle = io.popen("zenity --entry --title='Set Threshold' --text='Enter the threshold value:'")
    if handle then
        local input = handle:read("*a")
        handle:close()

        -- Trim whitespace
        input = input and input:match("^%s*(.-)%s*$") or ""

        -- Handle cancellation
        if input == "" then
            Create_popup("Threshold update canceled.")
            return
        end

        -- Convert to number and validate
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


-- Menu action for setting the port
local function port_action()
    local handle = io.popen("zenity --entry --title='Set Port' --text='Enter the port number:'")
    if handle then
        local input = handle:read("*a")
        handle:close()

        -- Trim whitespace
        input = input and input:match("^%s*(.-)%s*$") or ""

        -- Handle cancellation
        if input == "" then
            Create_popup("Port update canceled.")
            return
        end

        -- Convert to number and validate
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

-- Gui stuff
if gui_enabled() then
    register_menu("DDoS Detection/Set Threshold", threshold_action, MENU_TOOLS_UNSORTED)
    register_menu("DDoS Detection/Set Port", port_action, MENU_TOOLS_UNSORTED)
end

-- Functions to handle packet analysis for SYNFlood
function SynFlood.dissector(buffer, pinfo, tree)
    -- TODO: Implement SYN flood detection logic here
end

-- Registering of the dissectors
register_postdissector(SynFlood)

