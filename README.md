# parse-esf

A Python utility for parsing Apple Endpoint Security Framework (ESF) JSONL log files into CSV format for analysis.

## Overview

macOS Endpoint Security Framework events can be exported as JSONL (newline-delimited JSON). This tool parses those logs and flattens them into a structured CSV, making it easy to analyze in Excel, pandas, or any data tool.

## Usage

```bash
python parse_esf.py <input> [output.csv]
```

If no output path is provided, the output CSV is saved to the same location as the input file with a `.csv` extension.

### Examples

```bash
python parse_esf.py esf_events.json
python parse_esf.py esf_events.json esf_events.csv
```

## Output Fields

| Field | Description |
|---|---|
| `date_time_local` | Event timestamp converted to local system time |
| `date_time_utc` | Event timestamp in UTC |
| `mach_time` | Mach absolute time |
| `global_seq_num` | Global sequence number |
| `seq_num` | Per-event sequence number |
| `event_type_id` | ESF event type identifier |
| `action_type` | Action type (AUTH or NOTIFY) |
| `result_type` | Result type |
| `result_auth` | Auth result value |
| `result_flags` | Result flags |
| `process_pid` | Process ID |
| `process_ppid` | Parent process ID |
| `process_uid` | Real user ID |
| `process_gid` | Real group ID |
| `process_euid` | Effective user ID |
| `process_session_id` | Session ID |
| `process_exe` | Path to the executable |
| `process_signing_id` | Code signing identifier |
| `process_team_id` | Team ID |
| `process_is_platform_binary` | Whether it is an Apple platform binary |
| `process_codesigning_flags` | Codesigning flags |
| `process_start_time` | Process start time |
| `event_key` | Top-level key of the event data |
| `cmdline` | Full command line arguments for exec events |
| `paths` | Pipe-separated list of paths found in the event |
| `raw_event` | Full event data as JSON |

## Supported ESF Events

Reference: [es_events_t — Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_events_t)

### File-System Events

| Event | Description |
|---|---|
| `access` | Checking of a file's access permission |
| `clone` | Cloning of a file |
| `copyfile` | Copying of a file |
| `close` | Closing of a file |
| `create` | Creation of a file |
| `dup` | Duplication of a file descriptor |
| `exchangedata` | Exchange of data between two files |
| `fcntl` | Manipulation of a file descriptor |
| `open` | Opening of a file |
| `rename` | Renaming of a file |
| `write` | Writing of data to a file |
| `truncate` | Truncation of a file |
| `lookup` | Lookup of a file's path |
| `searchfs` | Search operation on a volume or mounted file system |

### File Metadata Events

| Event | Description |
|---|---|
| `deleteextattr` | Deletion of an extended attribute from a file |
| `fsgetpath` | Retrieval of a file-system path |
| `getattrlist` | Retrieval of attributes from a file |
| `getextattr` | Retrieval of an extended attribute from a file |
| `listextattr` | Retrieval of multiple extended attributes from a file |
| `readdir` | Reading of a file-system directory |
| `setacl` | Setting of a file's access control list |
| `setattrlist` | Setting of an attribute of a file |
| `setextattr` | Setting of an extended attribute of a file |
| `setflags` | Setting of a file's flags |
| `setmode` | Setting of a file's mode |
| `setowner` | Setting of a file's owner |
| `stat` | Retrieval of a file's status |
| `utimes` | Change to a file's access time or modification time |

### File Provider Events

| Event | Description |
|---|---|
| `file_provider_materialize` | Materialization of a file provider |
| `file_provider_update` | Update to a file provider |

### Symbolic Link Events

| Event | Description |
|---|---|
| `link` | Creation of a hard link |
| `readlink` | Reading of a symbolic link |
| `unlink` | Deletion of a file |

### File System Mounting Events

| Event | Description |
|---|---|
| `mount` | Mounting of a file system |
| `unmount` | Unmounting of a file system |
| `remount` | Remounting of a file system |

### Memory Mapping Events

| Event | Description |
|---|---|
| `mmap` | Mapping of memory to a file |
| `mprotect` | Change to protection of memory-mapped pages |

### Process Events

| Event | Description |
|---|---|
| `chdir` | Change to a process's working directory |
| `chroot` | Change to a process's root directory |
| `exec` | Execution of a process |
| `fork` | Forking of a process |
| `proc_check` | Retrieval of process information |
| `signal` | Sending of a signal to a process |
| `exit` | A process exiting |

### Interprocess Events

| Event | Description |
|---|---|
| `proc_suspend_resume` | Call to suspend, resume, or shut down sockets for a process |
| `trace` | Attempt by one process to attach to another |
| `remote_thread_create` | Attempt by one process to spawn a thread in another |

### Task Port Events

| Event | Description |
|---|---|
| `get_task` | Retrieval of a task's control port |
| `get_task_read` | Retrieval of a task's read port |
| `get_task_inspect` | Retrieval of a task's inspect port |
| `get_task_name` | Retrieval of a task's name port |

### User and Group ID Events

| Event | Description |
|---|---|
| `setuid` | Change to a process's user ID |
| `setgid` | Change to a process's group ID |
| `seteuid` | Change to a process's effective user ID |
| `setegid` | Change to a process's effective group ID |
| `setreuid` | Change to a process's real and effective user IDs |
| `setregid` | Change to a process's real and effective group IDs |

### Code Signing Events

| Event | Description |
|---|---|
| `cs_invalidated` | Invalidation of a process's code signing status |

### Socket Events

| Event | Description |
|---|---|
| `uipc_bind` | Binding of a socket to a path |
| `uipc_connect` | Connection of a socket |

### Clock Events

| Event | Description |
|---|---|
| `settime` | Modification of the system time |

### Kernel Events

| Event | Description |
|---|---|
| `iokit_open` | Opening of an IOKit device |
| `kextload` | Loading of a Kernel Extension (KEXT) |
| `kextunload` | Unloading of a Kernel Extension (KEXT) |

### Pseudoterminal Events

| Event | Description |
|---|---|
| `pty_close` | Closing of a pseudoterminal device |
| `pty_grant` | Granting of a pseudoterminal device to a user |

## Requirements

- Python 3.x
- No external dependencies

## Input Format

The input file should be a UTF-16 encoded JSONL file as exported by ESF tools. Each line (or concatenated stream) should contain a valid ESF event JSON object.
