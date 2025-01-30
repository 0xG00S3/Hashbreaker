# HashBreaker Hashcat Control Panel

⚠️ **EDUCATIONAL USE ONLY**: This software is provided strictly for educational purposes. Any use of this software for unauthorized access, or malicious activities is strictly prohibited. Users must ensure they have explicit permission and legal authority for any password recovery or hash cracking activities.

A modern, web-based GUI for Hashcat that provides an intuitive interface for hash cracking operations. This application combines the power of Hashcat's command-line functionality with a user-friendly web interface, making it easier to manage and monitor hash cracking tasks.

![HashBreaker Hashcat Control Panel](images/hashcat.png)

## Features

- **Modern Web Interface**: Clean, dark-themed UI with responsive design
- **Hash Type Search**: Easy-to-use dropdown with search functionality for all Hashcat modes
  - Categorized hash types
  - Example hashes for each type
  - Direct mode number input
- **File Management**:
  - Paste or upload hashes
  - Save/load hash files
  - Automatic temporary file handling
- **Real-time Monitoring**:
  - Live cracking status updates
  - Cracked hash display
  - Command output window
  - Success notifications
- **Configuration Management**:
  - Configurable paths for all components
  - Workload profile selection
  - Potfile management
  - Rules support
- **Output Management**:
  - Save cracked hashes to file
  - Save command output to file
  - Clear and scroll controls
  - Organized display of results

## Requirements

- Python 3.x
- Flask
- psutil
- Hashcat
- Modern web browser
- Windows OS (for native file dialogs)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/hashbreaker.git
cd hashbreaker
```

2. Install the required Python packages:
```bash
pip install -r requirements.txt
```

3. Configure your paths in the administration panel (⚙️) or directly in `config.json`:
   - Hashcat executable location
   - Wordlists directory
   - Rules directory
   - Hash types file
   - Potfile location
   - Temporary files directory

## Usage

1. Start the server:
```bash
python server.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

3. Configure your paths in the administration panel (⚙️)

4. To crack hashes:
   - Select a hash type from the dropdown or enter the mode number (default: NTLM)
   - Paste your hashes or upload a hash file
   - Select a wordlist
   - (Optional) Select a rule set
   - Click "Start Cracking"

## Features in Detail

### Hash Type Selection
- Search by name, mode number, or example hash
- Organized categories
- Quick mode number input
- Example hashes for reference
- Default: NTLM (mode 1000)

### Hash Input Methods
- Direct paste in textarea
- File upload
- Automatic hash counting
- Temporary file management

### Cracking Control
- Start/Stop functionality
- Workload profile selection (-w)
- Command preview
- Real-time status updates

### Output Management
- Live cracking status
- Cracked hash display
- Command output window
- Save functionality for all outputs

### Administration
- Configurable paths
- Potfile management
- Directory selection dialogs
- Configuration persistence

## Security Notes

- This application is designed for educational purposes only
- Any use for unauthorized access or malicious activities is strictly prohibited
- Users must ensure they have explicit permission for password recovery activities
- Keep your hashcat and wordlists updated
- Secure your installation appropriately

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Hashcat team for their incredible hash cracking tool
- Flask team for the web framework
- All contributors and testers

## Support

For support, please open an issue on the GitHub repository.

## Initial Configuration

After installation, you'll need to configure the application paths in the Administration Panel:

1. Click the "⚙️ Administration Panel" button at the top of the interface
2. Configure the following paths:
   - **Hashcat Executable**: Path to your `hashcat.exe` (default: `C:\hashcat\hashcat.exe`)
   - **Wordlists Directory**: Path to your wordlists folder (default: `C:\hashcat\wordlists`)
   - **Rules Directory**: Path to your rules folder (default: `C:\hashcat\rules`)
   - **Hash Types File**: Path to the hash types definition file (default: `C:\hashcat\hash_types.txt`)
   - **Potfile Location**: Path to your hashcat potfile (default: `C:\hashcat\hashcat.potfile`)
   - **Temporary Files Directory**: Path for temporary hash files (default: `C:\Windows\Temp`)
   - **Workload Profile**: Select your preferred workload profile (default: High)
3. Click "Save Configuration" to save your settings

These settings will be saved and loaded automatically each time you start the application. 
