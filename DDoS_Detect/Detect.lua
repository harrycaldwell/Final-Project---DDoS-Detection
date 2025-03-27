local plugin_info = {
    version = "1.0.0",
    description = "DDoS Detector Plugin",
    author = "Harry Caldwell",
    repository = "https://github.com/harrycaldwell/Final-Project---DDoS-Detection"
}


-- Creation of required variables and "proto" functions
-- Proto Declarations
local SynFlood = proto("SYNFlood", "SYN Flood Attack Detection")

-- Variable Declarations
local threshold = 0
local counter = 0
local port = 80

-- Menu Gui stuff
local threshold_menu = {
    title = "Set Threshold",
    action = function()
        -- Create the prompt to allow the user to enter a value for the threshold
        local handle = io.popen("zenity --entry --title='Set Threshold' --text='Enter the threshold value:'")
        local input = nil
        if handle then
            input = handle:read("*a")
            handle:close()
            else
                Create_popup("Failed to open input prompt.")
                return
            end

            -- Trim whitespace from input
            input = input:match("^%s*(.-)%s*$")

            -- Check if input is empty or invalid
            if not input or input == "" then
                Create_popup("Threshold update canceled.")
                return
            end

            -- Convert the input into a number
            local new_threshold = tonumber(input)
            if new_threshold then
                Set_threshold(new_threshold)
            else
                Create_popup("Invalid Threshold Value. Please use a non-negative number.")
            end
        end,
    path = "Analyze/DDoS Detection/Set Threshold"
    }
local port_menu = {
    title = "Set Port",
    action = function()
        -- Create the prompt to allow the user to enter a value for the port
        local handle = io.popen("zenity --entry --title='Set Port' --text='Enter the port number:'")
        local input = nil
        if handle then
            input = handle:read("*a")
            handle:close()
            else
                Create_popup("Failed to open input prompt.")
                return
            end

        -- Trim whitespace from input
        input = input:match("^%s*(.-)%s*$")

        -- Check if input is empty or invalid
        if not input or input == "" then
            Create_popup("Port update canceled.")
            return
        end

        -- Convert the input into a number
        local new_port = tonumber(input)
        if new_port then
            Set_port(new_port)
            else
                Create_popup("Invalid Port Number. Please use a non-negative number.")
            end
        end,
    path = "Analyze/DDoS Detection/Set Port"
    }

if gui_enabled() == true then
    -- Register the menus
    register_menu(port_menu)
    register_menu(threshold_menu)
end

-- TODO: Functionality for if Wireshark is not running in GUI mode
if gui_enabled() == false then

    
end


-- Functions to create Pop-up windows
function Create_popup(message)
    -- This function uses zenity to create the pop up message
    os.execute("zenity --info --text=\"" .. message .. "\"")
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

-- Functions to handle packet analysis for SYNFlood
function SynFlood.dissector(buffer, pinfo, tree)
    -- TODO: Write script that enables functionality for this dissector

end

-- Registering of the dissectors
register_postdissector(SynFlood)

-- Alert Functions
function Alert()
    -- TODO: Implement alert functionality
end