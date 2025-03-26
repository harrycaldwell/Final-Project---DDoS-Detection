-- DDoS Detector plugin
-- Made by Harry Caldwell

-- Creation of required variables and "proto" functions
local SynFlood = proto("SYNFlood", "SYN Flood Attack Detection")
public int threshold = 0
public int counter = 0

-- Functions to create Pop-up windows
local function create_popup(message)
    -- This function uses zenity to create the pop up message so that no additional dependencies are required
    os.execute("zenity --info --text=\"" .. message .. "\"")
end

-- Function to set the threshold
function set_threshold(new_threshold)
    if type(new_threshold) == "number" and new_threshold >= 0 then
        threshold = new_threshold
        print("Threshold updated to: " .. threshold)
    else
        print("Invalid threshold value. Please provide a non-negative number.")
    end
end

-- Functions to handle packet analysis (data passthrough)
function SynFlood.dissector(buffer, pinfo, tree)


-- Registering of the dissectors
regiseter_postdissector(SynFlood)
regiseter_postdissector()