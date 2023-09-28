# Ensure the script stops on any errors
$ErrorActionPreference = 'Stop'

# Name of the output zip file
$zipFileName = "Encryptable_Download.zip"

# Name of your main Python script (the entry point)
$mainScript = "Encryptable.py"

# Run PyInstaller to generate the executable
& pyinstaller --onefile --windowed --add-data "icons\IconOnly.png;icons/" --add-data "icons\hide_password_icon.png;icons/" --add-data "icons\show_password_icon.png;icons/" --add-data "accounts_database.db;." $mainScript

# Check if the zip file already exists and remove it
if (Test-Path $zipFileName) {
    Remove-Item $zipFileName
}

# Paths to the files and folders you want to zip up
$itemsToZip = @(
    ".\dist\Encryptable.exe",  # Assuming your executable name is Encryptable.exe
    ".\icons",
    ".\accounts_database.db"
    ".\README.md"
)

# Create the zip file
Compress-Archive -Path $itemsToZip -DestinationPath $zipFileName

# Optionally, delete the 'dist' and 'build' directories and the .spec file to clean up
Remove-Item "dist" -Recurse -Force
Remove-Item "build" -Recurse -Force
Remove-Item "Encryptable.spec" -Force

Write-Output "Packaging completed. '$zipFileName' is ready for distribution!"
