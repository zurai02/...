-- Example Luau script

local Players = game:GetService("Players")

local function greet(player: Player)
	print("Hello, " .. player.Name)
end

Players.PlayerAdded:Connect(greet)
