# MetaTrader 5 Connection Analyzer

A zero-dependency Python script that recursively scans MetaTrader 5 terminal log folders, extracts all network connection lost and re-authorized events, and produces three structured plain text reports covering outage statistics broken down by terminal, account, and access server.

---

## What it does

MT5 writes a timestamped journal line every time a terminal loses its broker connection and every time it re-authorizes. This script collects all of those events across every terminal installation and account in one pass, correlates them into matched disconnect/reconnect pairs, and reports:

- Min / max / avg / median / stdev outage durations (connection lost → authorized, authorized → synchronized, total lost → synchronized)
- Breakdowns per terminal, per account, per access server
- Cross-terminal account tracking — useful when the same account runs on multiple VPS instances
- Spike detection: outages that land in the slowest 5% or exceed 10,000 ms are flagged automatically
- Auto-switch vs unexpected drop classification — voluntary server quality upgrades are separated from true connection failures
- Multi-auth detection: events where the terminal re-authorized more than once before sync was confirmed
- Trade correlation: any market order requests that fired inside an outage window are listed alongside the event, with post-reconnect fill detection within 60 seconds
- Hourly and per date heatmaps to identify which server-time hours and days produce the most outages
- Recurring disconnect time detection: HH:MM slots that appear on 3+ separate dates are flagged as likely scheduled maintenance or broker rollover windows
- Ping statistics and distribution per access server

---

## Requirements

- Python 3.10 or newer
- No third-party packages — standard library only (`argparse`, `os`, `re`, `statistics`, `sys`, `collections`, `datetime`)

---

## Usage

**Option 1 — place in your Terminal root folder (simplest)**

Place `parse_connection_logs.py` in your MetaQuotes `Terminal` root folder and run it with no arguments:

```
C:\Users\<you>\AppData\Roaming\MetaQuotes\Terminal\
├── DDF819BCA69FB509\
│   └── Logs\
│       ├── 20260522.log
│       └── 20260521.log
├── A3F92C1B44D7E110\
│   └── Logs\
│       └── 20260522.log
└── parse_connection_logs.py   ← place here
```

```bash
python parse_connection_logs.py
```

**Option 2 — specify paths explicitly**

```bash
python parse_connection_logs.py --source "C:\path\to\Terminal" --output "C:\path\to\reports"
```

| Argument | Default | Description |
|----------|---------|-------------|
| `--source` | Script folder | Root folder containing terminal hash subfolders with `Logs/` directories |
| `--output` | Same as `--source` | Folder to write the three output files into |

Three output files are written to the output folder.

---

## Output files

| File | Contents |
|------|----------|
| `connection_events.txt` | Every matched disconnect/reconnect pair with terminal, account, date, timestamps, outage durations, access server, ping, connection type, client IP, open positions/orders, and trade activity counts |
| `connection_summary.txt` | Full statistical breakdown — per terminal, per account, per access server, auto-switches vs unexpected drops, global totals, spike analysis, hourly breakdown, per-date breakdown, and recurring disconnect times |
| `connection_report.txt` | Quick-glance report — top 10 worst outages, access server usage and ping stats, outages per account, trades affected, hourly heatmap, and full spike list |

---

## Console output

```
Scanning from: C:\...\MetaQuotes\Terminal
Log files found: 20

  DDF819BCA69FB509  12 files, 38 events
  A3F92C1B44D7E110  8 files, 21 events

Connection events matched: 59
Trade events indexed:      312

  written to:
    connection_events.txt
    connection_summary.txt
    connection_report.txt

  59 events (14 auto-sw / 45 drops) | 2 terminals | 3 accounts | 2 servers
  outage  min=312 ms  max=42180 ms  avg=4821 ms  med=2340 ms
  total↓  min=890 ms  max=44510 ms  avg=6103 ms
  ping    min=2.10 ms  max=38.40 ms  avg=8.73 ms
  spikes >=10000 ms: 7
  trades in outage windows: 4  post-fills: 3
```

---

## Configuration

Constants at the top of the script control spike detection and correlation windows:

```python
SPIKE_PERCENTILE = 95        # top N% flagged as long-outage spikes
SPIKE_MIN_MS     = 10_000    # absolute spike floor ms (10 s)
RETRY_WINDOW_MS  = 60_000    # look 60 s after reconnect for post-reconnect fills
AUTO_TRIGGER_MS  = 5_000     # if auto-connect happened within this ms before lost, flag as voluntary
MAX_OUTAGE_MS    = 3_600_000 # 1-hour hard cap — pairings exceeding this are discarded as phantom cross-session matches
```

An outage is flagged as a spike if its duration meets **either** the percentile threshold **or** the absolute floor — whichever is higher. Adjust these to suit your broker and infrastructure.

---

## Event terminology

| Term | Meaning |
|------|---------|
| **Outage ms** | Time from `connection lost` to `authorized` |
| **SyncDelta ms** | Time from `authorized` to `terminal synchronized` |
| **TotalDown ms** | Full outage: `connection lost` → `terminal synchronized` |
| **DROP** | Unexpected connection failure |
| **AUTO-SW** | Voluntary auto-connect to a better access point (MT5 quality upgrade) |
| **Multi-auth** | Terminal re-authorized more than once before sync was confirmed |

---

## Log line format

The script expects the standard MT5 Network journal format. The three key lines it correlates are:

```
07:58:12.044  Network  '243672':  connection to BrokerName-Server lost
07:58:24.301  Network  '243672':  authorized on BrokerName-Server through Access Server NY-3 (ping: 8.42 ms, build 4755)
07:58:24.890  Network  '243672':  terminal synchronized (positions: 2, orders: 0, symbols: 1234)
```

It also optionally reads:

```
07:58:10.981  Network  '243672':  auto connecting to a better access point with 92% quality (previous: 71%)
07:58:11.002  Network  '243672':  previous successful authorization performed from 185.212.x.x
```

---

## Known limitations

- **Single-day log files only.** MT5 writes one log file per calendar day. Outages that span midnight (connection lost at 23:59, reconnected at 00:01) are not matched because they cross file boundaries.
- **Same-day MT5 restarts.** If MT5 crashes and restarts within the same calendar day, the resulting session boundary is handled via the `MAX_OUTAGE_MS` cap. Any genuine outage exceeding 1 hour would not be captured. Adjust `MAX_OUTAGE_MS` at the top of the script if your environment requires a higher ceiling.
- **Timestamp precision.** All timestamps are within a single calendar day (milliseconds from midnight). Cross-day correlation is not supported.

---

## License

Copyright (C) 2026 minn0x  
Licensed under the [GNU General Public License v3.0](LICENSE)
