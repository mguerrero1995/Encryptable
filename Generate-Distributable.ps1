# Ensure the script stops on any errors
$ErrorActionPreference = 'Stop'

# Read the version from the config.json
# $configContent = Get-Content -Path "C:\EncryptableConfig\config.json" | ConvertFrom-Json
# $version = $configContent.application.version

# Name of the output zip file
$zipFileName = "Encryptable_Download.zip"

# Name of your main Python script (the entry point)
$mainScript = "Encryptable.py"

# Encrypt the config file before packaging
& python C:\EncryptableConfig\encrypt_config.py

# Run PyInstaller to generate the executable
& pyinstaller --onefile --windowed --icon=".\resources\icons\IconOnly.ico" --add-data "resources\icons\IconOnly.png;resources/icons/" --add-data "resources\icons\hide_password_icon.png;resources/icons/" --add-data "resources\icons\show_password_icon.png;resources/icons/" --add-data "resources\accounts_database.db;." $mainScript

# Check if the zip file already exists and remove it
if (Test-Path $zipFileName) {
    Remove-Item $zipFileName
}

# Paths to the files and folders you want to zip up
$itemsToZip = @(
    ".\dist\Encryptable.exe",  # Assuming your executable name is Encryptable.exe
    ".\resources",
    ".\README.md",
    ".\Privacy Policy.md"
)

# Create the zip file
Compress-Archive -Path $itemsToZip -DestinationPath $zipFileName

# Optionally, delete the 'dist' and 'build' directories and the .spec file to clean up
Remove-Item "dist" -Recurse -Force
Remove-Item "build" -Recurse -Force
Remove-Item "Encryptable.spec" -Force

Write-Output "Packaging completed. '$zipFileName' is ready for distribution!"
