# PisoWiFi Admin Terminal Commands

This document lists all available commands in the PisoWiFi Admin System Terminal.

## System Information Commands

### `uptime`
Shows system uptime and load average.

### `date`
Displays current date and time.

### `whoami`
Shows the current user.

### `uname -a`
Displays system information including kernel version.

### `lscpu`
Shows CPU information and architecture.

### `lsblk`
Lists all block devices (disks and partitions).

### `df -h`
Shows disk space usage in human-readable format.

### `free -m`
Displays memory usage in megabytes.

### `ps aux`
Lists all running processes.

## Network Commands

### `netstat -tuln`
Shows listening ports and network connections.

### `ss -tuln`
Modern alternative to netstat for socket statistics.

### `ifconfig` / `ip addr`
Displays network interface configuration.

### `ip route`
Shows routing table.

### `ping [host]`
Tests connectivity to a host.

### `traceroute [host]`
Shows network path to a host.

### `nslookup [domain]`
Performs DNS lookup.

### `dig [domain]`
Advanced DNS lookup tool.

### `hostname`
Shows system hostname.

## File System Commands

### `ls` / `dir`
Lists directory contents.

### `pwd`
Shows current working directory.

### `cat [file]`
Displays file contents.

### `tail [file]`
Shows last lines of a file.

### `head [file]`
Shows first lines of a file.

### `grep [pattern] [file]`
Searches for text patterns in files.

### `find [path] [options]`
Searches for files and directories.

### `du [directory]`
Shows disk usage of files and directories.

## System Management Commands

### `systemctl [command]`
Controls systemd services.

### `journalctl [options]`
Views system logs.

### `service [name] [action]`
Manages system services.

### `crontab -l`
Lists scheduled cron jobs.

### `mount`
Shows mounted filesystems.

## Security Commands

### `iptables -L`
Lists firewall rules.

## Command Validation

All commands are validated against an allowed list to prevent unauthorized system access. Only the commands listed above are permitted.

## Usage Notes

- Commands are executed with the permissions of the PisoWiFi service user
- Output is limited to 10 seconds execution time
- Error messages are displayed in red text
- Command history is maintained for the current session
- Output can be copied to clipboard using the Copy button

## Safety Features

- Command whitelist prevents execution of potentially harmful commands
- Execution timeout prevents hanging processes
- Input validation prevents command injection
- Error handling provides clear feedback for failed commands