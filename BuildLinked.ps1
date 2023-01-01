# Set Working Directory
Split-Path $MyInvocation.MyCommand.Path | Push-Location
[Environment]::CurrentDirectory = $PWD

Remove-Item "$env:RELOADEDIIMODS/Colored_Chat_Icon_Bg/*" -Force -Recurse
dotnet publish "./Colored_Chat_Icon_Bg.csproj" -c Release -o "$env:RELOADEDIIMODS/Colored_Chat_Icon_Bg" /p:OutputPath="./bin/Release" /p:ReloadedILLink="true"

# Restore Working Directory
Pop-Location