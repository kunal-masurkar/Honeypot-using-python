# Python Honeypot

A simple low-interaction honeypot implementation in Python that monitors multiple ports and logs connection attempts. This honeypot is designed for educational purposes and to study malicious behavior patterns.

## Features

- Monitor multiple ports simultaneously
- Log connection attempts with timestamps
- Simulate basic service responses (SSH, HTTP, HTTPS)
- Capture and log incoming data
- Thread-safe implementation
- Detailed logging to file

## Requirements

- Python 3.6 or higher
- No external dependencies required

## Usage

1. Run the honeypot with default settings (monitoring ports 22, 80, and 443):
```bash
python honeypot.py
```

2. To modify the ports being monitored, edit the `ports_to_monitor` list in the `main()` function.

3. The honeypot will create a log file named `honeypot.log` in the same directory.

## Security Notice

⚠️ **IMPORTANT**: This honeypot should only be used in controlled environments and with proper authorization. Running a honeypot without permission could be illegal in some jurisdictions.

## Logging

The honeypot logs the following information:
- Connection attempts with timestamps
- Source IP addresses
- Port numbers
- Any data received from the connection
- Errors and exceptions

Logs are stored in `honeypot.log` with the following format:
```
YYYY-MM-DD HH:MM:SS - LEVEL - Message
```

## Stopping the Honeypot

Press `Ctrl+C` to gracefully stop the honeypot. All connections will be closed and the program will exit cleanly.

## Customization

You can customize the honeypot by:
1. Modifying the ports to monitor
2. Changing the log file location
3. Adding more sophisticated response handling
4. Implementing additional security measures

## Disclaimer

This honeypot is provided for educational purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have proper authorization before deploying any honeypot in a network. 
