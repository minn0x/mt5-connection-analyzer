#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# mt5-connection-analyzer / parse_connection_logs.py
#
# Version: 1.0.0
#
# Place this script in your MetaQuotes/Terminal root folder.
# It recursively finds all *.log files inside every terminal installation
# subfolder, parses MT5 Network connection-lost / re-authorized events, and
# writes:
#   connection_events.txt   – every matched disconnect/reconnect pair
#   connection_summary.txt  – stats per terminal, per account, per server,
#                             global totals, spike analysis, hourly breakdown
#   connection_report.txt   – quick-glance report (worst outages, server/ping,
#                             trades affected during outage windows)
# ---------------------------------------------------------------------------

import argparse
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime

__version__ = '1.0.0'

# ---------------------------------------------------------------------------
SPIKE_PERCENTILE = 95        # top N% flagged as long-outage spikes
SPIKE_MIN_MS     = 10_000    # absolute spike floor ms (10 s)
RETRY_WINDOW_MS  = 60_000    # look 60 s after reconnect for post-reconnect fills
AUTO_TRIGGER_MS  = 5_000     # if auto-connect happened within this ms before lost, flag as voluntary
MAX_OUTAGE_MS    = 3_600_000  # 1 hour hard cap — any pairing exceeding this is a phantom cross-session match

# ---------------------------------------------------------------------------
# Regex patterns – support HH:MM:SS.mmm and HHMMSS.mmm timestamps,
# tabs or spaces, quoted/unquoted account ids, colon-or-not after account.
# ---------------------------------------------------------------------------

LOST_PAT = re.compile(
    r'(\d{2}:?\d{2}:?\d{2}\.\d{3})\s+Network\s+'
    r"'?(\d+)'?:?\s+connection to (.+?) lost",
    re.IGNORECASE
)

# Server name captured up to the opening '(' to handle "NY-3", "- NY-NEW-2", etc.
AUTH_PAT = re.compile(
    r'(\d{2}:?\d{2}:?\d{2}\.\d{3})\s+Network\s+'
    r"'?(\d+)'?:?\s+authorized on (.+?)\s+through Access Server\s+(.+?)\s*\("
    r'ping:?\s*([\d.]+)\s*ms.*?build\s+(\d+)',
    re.IGNORECASE
)

# Previous auth IP: "previous successful authorization performed from X.X.X.X on DATE"
PREV_AUTH_PAT = re.compile(
    r'(\d{2}:?\d{2}:?\d{2}\.\d{3})\s+Network\s+'
    r"'?(\d+)'?:?\s+previous successful authorization performed from\s+([\d.]+)",
    re.IGNORECASE
)

# Terminal synchronized: includes position/order/symbol counts
SYNC_PAT = re.compile(
    r'(\d{2}:?\d{2}:?\d{2}\.\d{3})\s+Network\s+'
    r"'?(\d+)'?:?\s+terminal synchronized.*?(\d+)\s+positions[,\s]+(\d+)\s+orders[,\s]+(\d+)\s+symbols",
    re.IGNORECASE
)

# Trading has been enabled
TRADING_PAT = re.compile(
    r'(\d{2}:?\d{2}:?\d{2}\.\d{3})\s+Network\s+'
    r"'?(\d+)'?:?\s+trading has been enabled",
    re.IGNORECASE
)

# Auto-connect to better access point (voluntary server switch)
AUTO_PAT = re.compile(
    r'(\d{2}:?\d{2}:?\d{2}\.\d{3})\s+Network\s+'
    r"'?(\d+)'?:?\s+auto connecting to a better access point with\s+(\d+)\s*%\s*quality"
    r'(?:[^(]*\(previous:\s*(\d+)\s*%\))?',
    re.IGNORECASE
)

# Trade event patterns
TRADE_REQUEST_PAT = re.compile(
    r'(\d{2}:?\d{2}:?\d{2}\.\d{3})\s+Trades\s+'
    r"'?(\d+)'?:?\s+(market (?:buy|sell)\s+[\d.]+\s+\S+.*)",
    re.IGNORECASE
)
TRADE_ACCEPTED_PAT = re.compile(
    r'(\d{2}:?\d{2}:?\d{2}\.\d{3})\s+Trades\s+'
    r"'?(\d+)'?:?\s+(accepted market (?:buy|sell)\s+[\d.]+\s+\S+.*)",
    re.IGNORECASE
)
TRADE_DEAL_PAT = re.compile(
    r'(\d{2}:?\d{2}:?\d{2}\.\d{3})\s+Trades\s+'
    r"'?(\d+)'?:?\s+(deal \d+\s+(?:buy|sell)\s+[\d.]+\s+\S+\s+at\s+[\d.]+\s+done.*)",
    re.IGNORECASE
)
# Requires "market buy/sell" prefix to avoid false positives from broker
# system messages that incidentally contain "failed", "rejected", etc.
TRADE_FAILED_PAT = re.compile(
    r'(\d{2}:?\d{2}:?\d{2}\.\d{3})\s+Trades\s+'
    r"'?(\d+)'?:?\s+"
    r'(market\s+(?:buy|sell)\s+[\d.]+\s+\S+[^\n]{0,120}'
    r'(?:failed|rejected|cancelled|not\s+enough\s+money|invalid\s+price|absence\s+of\s+network)'
    r'[^\n]{0,80})',
    re.IGNORECASE
)

# ---------------------------------------------------------------------------
def detect_encoding(filepath):
    with open(filepath, 'rb') as f:
        bom = f.read(4)
    if bom[:3] == b'\xef\xbb\xbf':  return 'utf-8-sig'
    if bom[:4] in (b'\x00\x00\xfe\xff', b'\xff\xfe\x00\x00'): return 'utf-32'
    if bom[:2] == b'\xff\xfe': return 'utf-16-le'
    if bom[:2] == b'\xfe\xff': return 'utf-16-be'
    try:
        with open(filepath, 'r', encoding='utf-8') as f: f.read()
        return 'utf-8'
    except UnicodeDecodeError:
        return 'latin-1'

def find_log_files(root):
    """Recursively find all *.log files under any Logs/ subfolder."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        norm = dirpath.replace('\\', '/').lower()
        if norm.endswith('/logs'):
            terminal_id = os.path.basename(os.path.dirname(dirpath))
            for fname in filenames:
                if fname.lower().endswith('.log'):  # output files are .txt — never conflict
                    found.append((terminal_id, os.path.join(dirpath, fname)))
    if not found:
        print(
            'WARNING: No *.log files found under any Logs/ subfolder.\n'
            '  Expected structure: <root>/<hash>/Logs/YYYYMMDD.log\n'
            '  Place this script in your MetaQuotes/Terminal root folder,\n'
            '  or pass a custom path:  python parse_connection_logs.py --source <path>',
            file=sys.stderr
        )
    return found

def ts_to_ms(ts):
    """Convert HH:MM:SS.mmm or HHMMSS.mmm to milliseconds from midnight."""
    t = ts.replace(':', '')
    ms_part = int(t[7:10]) if len(t) >= 10 else 0  # guard: timestamp without ms component
    return (int(t[0:2]) * 3600 + int(t[2:4]) * 60 + int(t[4:6])) * 1000 + ms_part

def ms_delta(ts_later, ts_earlier):
    """Signed delta in ms, handling midnight wraparound.
    NOTE: assumes both timestamps are within the same calendar day (MT5 single-day log files).
    Cross-midnight outages are not fully supported.
    """
    d = ts_to_ms(ts_later) - ts_to_ms(ts_earlier)
    if d < 0: d += 86_400_000
    return d

def ms_to_hms(ms):
    """Format milliseconds as H:MM:SS.mmm."""
    ms = int(ms)
    s_total, ms_rem = divmod(ms, 1000)
    m_total, s_rem  = divmod(s_total, 60)
    h, m_rem        = divmod(m_total, 60)
    return f"{h}:{m_rem:02d}:{s_rem:02d}.{ms_rem:03d}"

def stats_block(values, indent="  "):
    if not values:
        return f"{indent}no data\n"
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    return (
        f"{indent}count   {len(values):>10}\n"
        f"{indent}min     {min(values):>12.3f} ms  ({ms_to_hms(min(values))})\n"
        f"{indent}max     {max(values):>12.3f} ms  ({ms_to_hms(max(values))})\n"
        f"{indent}avg     {statistics.mean(values):>12.3f} ms  ({ms_to_hms(statistics.mean(values))})\n"
        f"{indent}median  {statistics.median(values):>12.3f} ms  ({ms_to_hms(statistics.median(values))})\n"
        f"{indent}stdev   {sd:>12.3f} ms\n"
    )

def spike_threshold(values):
    if len(values) < 2: return SPIKE_MIN_MS
    p = sorted(values)
    return max(p[int(len(p) * SPIKE_PERCENTILE / 100)], SPIKE_MIN_MS)

def section(title, width=64):
    bar = "=" * width
    return f"\n{bar}\n{title}\n{bar}\n"

def subsection(title, width=58):
    bar = "-" * width
    return f"\n{bar}\n{title}\n{bar}\n"

def pair_row(label, values, indent="  "):
    return (
        f"{indent}{label:<22}  count={len(values):>4}  "
        f"min={min(values):>8.3f} ms  max={max(values):>8.3f} ms  "
        f"avg={statistics.mean(values):>8.3f} ms  "
        f"med={statistics.median(values):>8.3f} ms\n"
    )

def spike_row(label, total_rows, spike_rows, indent="  "):
    if not spike_rows: return ""
    sp_times = [r['outage_ms'] for r in spike_rows]
    pct = 100 * len(spike_rows) / len(total_rows)
    return (
        f"{indent}{label:<38}  {len(spike_rows):>4} spikes / {len(total_rows):>4} "
        f"({pct:.1f}%)  worst={max(sp_times):>8.3f} ms  avg={statistics.mean(sp_times):>8.3f} ms\n"
    )

def extract_instrument(detail):
    m = re.search(r'(?:buy|sell)\s+[\d.]+\s+(\S+)', detail, re.IGNORECASE)
    return m.group(1).upper() if m else ''

# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='MT5 Connection Log Analyzer v' + __version__
    )
    parser.add_argument(
        '--source', default=None,
        help='Root folder containing terminal hash subfolders with Logs/ directories. '
             'Defaults to the folder containing this script.'
    )
    parser.add_argument(
        '--output', default=None,
        help='Folder to write the three output files. Defaults to --source folder.'
    )
    args = parser.parse_args()

    source_dir = args.source if args.source else os.path.dirname(os.path.abspath(__file__))
    output_dir = args.output if args.output else source_dir
    os.makedirs(output_dir, exist_ok=True)

    # ---------------------------------------------------------------------------
    # PARSE
    # ---------------------------------------------------------------------------
    log_entries = find_log_files(source_dir)
    print(f"Scanning from: {source_dir}")
    print(f"Log files found: {len(log_entries)}")

    all_events   = []
    all_trades   = []
    term_summary = {}

    for terminal_id, filepath in sorted(log_entries):
        if terminal_id not in term_summary:
            term_summary[terminal_id] = {'files': 0, 'events': 0, 'errors': 0}
        encoding = detect_encoding(filepath)
        filename = os.path.basename(filepath)
        term_summary[terminal_id]['files'] += 1

        # Per-account state buffers
        pending      = {}   # account → pending lost event
        pending_auth = {}   # account → latest auth seen (before sync confirms it)
        last_auto    = {}   # account → (ts_ms, quality_new, quality_prev) of last AUTO line
        last_ip      = {}   # account → last seen client IP

        try:
            with open(filepath, 'r', encoding=encoding, errors='replace') as fh:
                for lineno, line in enumerate(fh, 1):

                    # --- trade lines ---
                    for tpat, ttype in (
                        (TRADE_REQUEST_PAT,  'request'),
                        (TRADE_ACCEPTED_PAT, 'accepted'),
                        (TRADE_DEAL_PAT,     'deal'),
                        (TRADE_FAILED_PAT,   'failed'),
                    ):
                        mt = tpat.search(line)
                        if mt:
                            all_trades.append({
                                'terminal': terminal_id,
                                'account':  mt.group(2),
                                'ts':       mt.group(1),
                                'ts_ms':    ts_to_ms(mt.group(1)),
                                'type':     ttype,
                                'detail':   mt.group(3).strip()[:120],
                                'file':     filename,
                                'line':     lineno,
                            })
                            break

                    # --- auto connect trigger ---
                    ma2 = AUTO_PAT.search(line)
                    if ma2:
                        acct = ma2.group(2)
                        last_auto[acct] = {
                            'ts_ms':       ts_to_ms(ma2.group(1)),
                            'quality_new':  int(ma2.group(3)),
                            'quality_prev': int(ma2.group(4)) if ma2.group(4) else None,
                        }
                        continue

                    # --- previous IP ---
                    mp = PREV_AUTH_PAT.search(line)
                    if mp:
                        last_ip[mp.group(2)] = mp.group(3)
                        continue

                    # --- connection lost ---
                    ml = LOST_PAT.search(line)
                    if ml:
                        ts, acct, broker = ml.group(1), ml.group(2), ml.group(3).strip()
                        lost_ms = ts_to_ms(ts)
                        auto_triggered = False
                        auto_quality_new = None
                        auto_quality_prev = None
                        if acct in last_auto:
                            delta = lost_ms - last_auto[acct]['ts_ms']
                            if 0 <= delta <= AUTO_TRIGGER_MS:
                                auto_triggered    = True
                                auto_quality_new  = last_auto[acct]['quality_new']
                                auto_quality_prev = last_auto[acct]['quality_prev']
                        pending[acct] = {
                            'lost_ts':          ts,
                            'lost_ts_ms':       lost_ms,
                            'broker':           broker,
                            'file':             filename,
                            'lost_line':        lineno,
                            'raw_lost':         line.rstrip(),
                            'auto_triggered':   auto_triggered,
                            'auto_quality_new': auto_quality_new,
                            'auto_quality_prev':auto_quality_prev,
                            'auth_count':       0,
                            'first_auth_ts':    None,
                            'first_auth_server':None,
                            'first_auth_ping':  None,
                        }
                        pending_auth.pop(acct, None)
                        continue

                    # --- authorized (may happen more than once before sync) ---
                    ma = AUTH_PAT.search(line)
                    if ma and ma.group(2) in pending and pending[ma.group(2)]['file'] == filename:
                        ts2, acct = ma.group(1), ma.group(2)
                        server = ma.group(4).strip().lstrip('- ').strip()
                        ping   = float(ma.group(5))
                        build  = int(ma.group(6))
                        p      = pending[acct]
                        p['auth_count'] += 1
                        if p['auth_count'] == 1:
                            p['first_auth_ts']     = ts2
                            p['first_auth_server'] = server
                            p['first_auth_ping']   = ping
                        # always overwrite with latest auth (last one wins)
                        pending_auth[acct] = {
                            'auth_ts':   ts2,
                            'auth_ms':   ts_to_ms(ts2),
                            'server':    server,
                            'ping_ms':   ping,
                            'build':     build,
                            'auth_line': lineno,
                            'raw_auth':  line.rstrip(),
                        }
                        continue

                    # --- terminal synchronized → finalize event ---
                    ms2 = SYNC_PAT.search(line)
                    if ms2 and ms2.group(2) in pending and ms2.group(2) in pending_auth:
                        acct    = ms2.group(2)
                        sync_ts = ms2.group(1)

                        # Cross-file guard: reject pairings where the pending 'lost'
                        # originated from a different log file. Prevents phantom
                        # multi-hour outages caused by a 'lost' at end-of-day N being
                        # matched with an 'auth' at start-of-day N+1.
                        if pending[acct]['file'] != filename:
                            pending.pop(acct, None)
                            pending_auth.pop(acct, None)
                            continue

                        p       = pending.pop(acct)
                        pa      = pending_auth.pop(acct)

                        auth_ms    = pa['auth_ms']
                        lost_ms    = p['lost_ts_ms']
                        sync_ms    = ts_to_ms(sync_ts)

                        outage_ms  = auth_ms - lost_ms
                        if outage_ms < 0: outage_ms += 86_400_000

                        # Sanity cap: reject phantom same-file pairings where MT5 restarted
                        # mid-day. A genuine outage cannot exceed MAX_OUTAGE_MS (1 hour).
                        # If lost→auth exceeds this, the 'lost' was from a previous MT5
                        # session in the same log file and the auth belongs to a new session.
                        if outage_ms > MAX_OUTAGE_MS:
                            continue
                        sync_delta = sync_ms - auth_ms
                        if sync_delta < 0: sync_delta += 86_400_000

                        # extract date from filename (MT5 log: YYYYMMDD.log)
                        date_str = filename.replace('.log', '') if re.match(r'\d{8}', filename) else ''

                        event = {
                            'terminal':          terminal_id,
                            'account':           acct,
                            'broker':            p['broker'],
                            'lost_ts':           p['lost_ts'],
                            'auth_ts':           pa['auth_ts'],
                            'sync_ts':           sync_ts,
                            'lost_ms':           lost_ms,
                            'auth_ms':           auth_ms,
                            'sync_ms':           sync_ms,
                            'outage_ms':         outage_ms,            # lost → auth
                            'sync_delta_ms':     sync_delta,           # auth → synchronized
                            'total_down_ms':     outage_ms + sync_delta,  # lost → synchronized
                            'server':            pa['server'],
                            'ping_ms':           pa['ping_ms'],
                            'build':             pa['build'],
                            'file':              filename,
                            'lost_line':         p['lost_line'],
                            'auth_line':         pa['auth_line'],
                            'raw_lost':          p['raw_lost'],
                            'raw_auth':          pa['raw_auth'],
                            'hour':              int(pa['auth_ts'].replace(':', '')[0:2]),  # reconnect hour
                            'date':              date_str,
                            'auto_triggered':    p['auto_triggered'],
                            'auto_quality_new':  p['auto_quality_new'],
                            'auto_quality_prev': p['auto_quality_prev'],
                            'auth_count':        p['auth_count'],
                            'first_auth_ts':     p['first_auth_ts'],
                            'first_auth_server': p['first_auth_server'],
                            'first_auth_ping':   p['first_auth_ping'],
                            'client_ip':         last_ip.get(acct, ''),
                            'open_positions':    int(ms2.group(3)),
                            'open_orders':       int(ms2.group(4)),
                            'symbols':           int(ms2.group(5)),
                        }
                        all_events.append(event)
                        term_summary[terminal_id]['events'] += 1

        except Exception as e:
            term_summary[terminal_id]['errors'] += 1
            print(f"  WARNING {filepath}: {e}")
        finally:
            # CRITICAL: discard any unmatched 'lost' events at end of file.
            # MT5 writes one log file per calendar day. A 'lost' at the last
            # line of day N with no matching 'auth' must NOT carry over to
            # day N+1 — that would produce phantom multi-hour outages.
            pending.clear()
            pending_auth.clear()
            last_auto.clear()

    # ---------------------------------------------------------------------------
    for term, info in sorted(term_summary.items()):
        err_str = f"  {info['errors']} errors" if info['errors'] else ""
        print(f"  {term}  {info['files']} files, {info['events']} events{err_str}")
    print(f"\nConnection events matched: {len(all_events)}")
    print(f"Trade events indexed:      {len(all_trades)}")

    # ---------------------------------------------------------------------------
    # Outage-window trade correlation
    # ---------------------------------------------------------------------------
    for ev in all_events:
        affected = []
        for t in all_trades:
            if (t['account'] == ev['account']
                    and ev['lost_ms'] <= t['ts_ms'] <= ev['auth_ms']):
                affected.append(t)

        affected_instruments = set(extract_instrument(t['detail']) for t in affected)
        post_exec = []
        for t in all_trades:
            if (t['account'] == ev['account']
                    and t['type'] in ('accepted', 'deal')
                    and ev['auth_ms'] < t['ts_ms'] <= ev['auth_ms'] + RETRY_WINDOW_MS
                    and extract_instrument(t['detail']) in affected_instruments):
                post_exec.append(t)

        ev['affected_trades'] = affected
        ev['post_exec_trades'] = post_exec

    # ---------------------------------------------------------------------------
    # Aggregates
    # ---------------------------------------------------------------------------
    all_outages      = [r['outage_ms']      for r in all_events]
    all_total_down   = [r['total_down_ms']  for r in all_events]
    all_sync_deltas  = [r['sync_delta_ms']  for r in all_events]
    all_pings        = [r['ping_ms']        for r in all_events]
    all_accounts     = sorted(set(r['account']  for r in all_events))
    all_servers      = sorted(set(r['server']   for r in all_events))
    all_brokers      = sorted(set(r['broker']   for r in all_events))
    terminals        = sorted(set(r['terminal'] for r in all_events))

    auto_events       = [r for r in all_events if r['auto_triggered']]
    manual_events     = [r for r in all_events if not r['auto_triggered']]
    multi_auth_events = [r for r in all_events if r['auth_count'] > 1]

    spike_thresh = spike_threshold(all_outages) if all_outages else SPIKE_MIN_MS
    spikes_all   = [r for r in all_events if r['outage_ms'] >= spike_thresh]

    total_affected = sum(len(e['affected_trades']) for e in all_events)
    total_post     = sum(len(e['post_exec_trades']) for e in all_events)

    # ---------------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------------
    def write_trade_block(out, event, indent="  "):
        aff  = event['affected_trades']
        post = event['post_exec_trades']
        if not aff and not post:
            return
        out.write(f"{indent}Trade activity during/after this outage:\n")
        if aff:
            out.write(f"{indent}  Inside outage window ({len(aff)}):\n")
            for t in aff:
                out.write(f"{indent}    [{t['type']:8}] {t['ts']}  {t['detail'][:90]}\n")
        if post:
            out.write(f"{indent}  Post-reconnect fills within 60 s ({len(post)}):\n")
            for t in post:
                out.write(f"{indent}    [{t['type']:8}] {t['ts']}  {t['detail'][:90]}\n")
        elif aff:
            out.write(f"{indent}  No post-reconnect fills found within 60 s.\n")

    def event_header(ev, indent="  "):
        kind  = "AUTO-SWITCH" if ev['auto_triggered'] else "OUTAGE"
        multi = f"  [re-authed x{ev['auth_count']}]" if ev['auth_count'] > 1 else ""
        q     = ""
        if ev['auto_triggered'] and ev['auto_quality_new']:
            q = f"  quality {ev['auto_quality_prev']}%→{ev['auto_quality_new']}%"
        return (
            f"{indent}[{kind}]{multi}{q}\n"
            f"{indent}  lost={ev['lost_ts']}  auth={ev['auth_ts']}  sync={ev['sync_ts']}\n"
            f"{indent}  outage={ev['outage_ms']:.0f} ms  sync_delta={ev['sync_delta_ms']:.0f} ms  "
            f"total_down={ev['total_down_ms']:.0f} ms  ({ms_to_hms(ev['total_down_ms'])})\n"
            f"{indent}  server={ev['server']}  ping={ev['ping_ms']:.2f} ms  "
            f"positions={ev['open_positions']}  orders={ev['open_orders']}\n"
            f"{indent}  client_ip={ev['client_ip']}\n"
        )

    # ---------------------------------------------------------------------------
    # OUTPUT 1: connection_events.txt
    # ---------------------------------------------------------------------------
    events_path = os.path.join(output_dir, "connection_events.txt")
    with open(events_path, 'w', encoding='utf-8') as out:
        out.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write(f"Source:    {source_dir}\n\n")
        hdr = (f"{'Terminal':<36}  {'Acct':<10}  {'Date':<12}  {'Lost':>12}  {'Auth':>12}  {'Sync':>12}  "
               f"{'Outage ms':>10}  {'SyncDelta':>10}  {'TotalDown':>10}  "
               f"{'Server':<12}  {'Ping':>7}  {'Type':<10}  {'IP':<16}  "
               f"{'Pos':>3}  {'Ord':>3}  {'Aff':>3}  {'Pst':>3}\n")
        out.write(hdr)
        out.write("-" * len(hdr) + "\n")
        for r in all_events:
            kind = "AUTO-SW" if r['auto_triggered'] else "DROP"
            out.write(
                f"{r['terminal']:<36}  {r['account']:<10}  {r['date']:<12}  {r['lost_ts']:>12}  "
                f"{r['auth_ts']:>12}  {r['sync_ts']:>12}  "
                f"{r['outage_ms']:>10.0f}  {r['sync_delta_ms']:>10.0f}  {r['total_down_ms']:>10.0f}  "
                f"{r['server']:<12}  {r['ping_ms']:>7.2f}  {kind:<10}  {r['client_ip']:<16}  "
                f"{r['open_positions']:>3}  {r['open_orders']:>3}  "
                f"{len(r['affected_trades']):>3}  {len(r['post_exec_trades']):>3}\n"
            )
        out.write(f"\n{len(all_events)} events\n")
        out.write("Outage ms   = connection lost → authorized\n")
        out.write("SyncDelta   = authorized → terminal synchronized\n")
        out.write("TotalDown   = connection lost → terminal synchronized\n")
        out.write("Type        = AUTO-SW (voluntary server switch) | DROP (unexpected)\n")
        out.write("Aff         = trade requests inside outage window\n")
        out.write("Pst         = post-reconnect fills within 60 s for affected instruments\n")

    # ---------------------------------------------------------------------------
    # OUTPUT 2: connection_summary.txt
    # ---------------------------------------------------------------------------
    summary_path = os.path.join(output_dir, "connection_summary.txt")
    with open(summary_path, 'w', encoding='utf-8') as out:
        out.write(section("CONNECTION OUTAGE SUMMARY"))
        out.write(f"  Generated:          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write(f"  Version:            {__version__}\n")
        out.write(f"  Source:             {source_dir}\n")
        out.write(f"  Log files:          {len(log_entries)}\n")
        out.write(f"  Terminals:          {len(terminals)}\n")
        out.write(f"  Accounts:           {len(all_accounts)}\n")
        out.write(f"  Brokers:            {', '.join(all_brokers)}\n")
        out.write(f"  Access Servers:     {', '.join(all_servers)}\n")
        out.write(f"  Total events:       {len(all_events)}\n")
        out.write(f"    Unexpected drops: {len(manual_events)}\n")
        out.write(f"    Auto-switches:    {len(auto_events)}  (voluntary server quality upgrade)\n")
        out.write(f"    Multi-auth:       {len(multi_auth_events)}  (re-authorized >1x before sync)\n")
        out.write(f"  Spike threshold:    {spike_thresh:.0f} ms  "
                  f"(top {100-SPIKE_PERCENTILE}% or >= {SPIKE_MIN_MS} ms)\n")
        out.write(f"  Trades in windows:  {total_affected}\n")
        out.write(f"  Post-fills found:   {total_post}\n")

        if not all_events:
            out.write("No connection events found.\n")
        else:

            # ----------------------------------------------------------------
            out.write(section("1. PER-TERMINAL BREAKDOWN"))
            for term in terminals:
                trows   = [r for r in all_events if r['terminal'] == term]
                ttimes  = [r['outage_ms']     for r in trows]
                ttotal  = [r['total_down_ms'] for r in trows]
                tsync   = [r['sync_delta_ms'] for r in trows]
                tpings  = [r['ping_ms']       for r in trows]
                tthresh = spike_threshold(ttimes)
                tspikes = [r for r in trows if r['outage_ms'] >= tthresh]
                taccts  = sorted(set(r['account'] for r in trows))
                tsrvs   = sorted(set(r['server']  for r in trows))
                tauto   = [r for r in trows if r['auto_triggered']]

                out.write(subsection(f"Terminal: {term}"))
                out.write(f"  Accounts:        {', '.join(taccts)}\n")
                out.write(f"  Access Servers:  {', '.join(tsrvs)}\n")
                out.write(f"  Auto-switches:   {len(tauto)} of {len(trows)}\n")
                out.write(f"\n  Auth → Sync delta stats:\n")
                out.write(stats_block(tsync))
                out.write(f"\n  Outage stats (lost → auth):\n")
                out.write(stats_block(ttimes))
                out.write(f"\n  Total downtime stats (lost → synchronized):\n")
                out.write(stats_block(ttotal))
                out.write(f"\n  Ping stats:\n")
                out.write(stats_block(tpings))
                out.write("\n  Per account:\n")
                for acct in taccts:
                    arows  = [r for r in trows if r['account'] == acct]
                    atimes = [r['outage_ms'] for r in arows]
                    out.write(pair_row(f"Account {acct}", atimes, indent="    "))
                out.write("\n  Per access server:\n")
                for srv in tsrvs:
                    srows  = [r for r in trows if r['server'] == srv]
                    stimes = [r['outage_ms'] for r in srows]
                    out.write(pair_row(srv, stimes, indent="    "))
                if tspikes:
                    out.write(f"\n  Spikes >={tthresh:.0f} ms:  {len(tspikes)} events\n")
                    for sp in sorted(tspikes, key=lambda x: x['outage_ms'], reverse=True):
                        out.write(event_header(sp, indent="    "))
                        write_trade_block(out, sp, indent="    ")
                else:
                    out.write(f"\n  No spikes above {tthresh:.0f} ms.\n")

            # ----------------------------------------------------------------
            out.write(section("2. PER-ACCOUNT BREAKDOWN (CROSS-TERMINAL)"))
            for acct in all_accounts:
                arows   = [r for r in all_events if r['account'] == acct]
                atimes  = [r['outage_ms']     for r in arows]
                atotal  = [r['total_down_ms'] for r in arows]
                apings  = [r['ping_ms']       for r in arows]
                athresh = spike_threshold(atimes)
                aspikes = [r for r in arows if r['outage_ms'] >= athresh]
                aterms  = sorted(set(r['terminal'] for r in arows))
                asrvs   = sorted(set(r['server']   for r in arows))
                aips    = sorted(set(r['client_ip'] for r in arows if r['client_ip']))

                out.write(subsection(f"Account: {acct}"))
                out.write(f"  Terminals:       {', '.join(aterms)}\n")
                out.write(f"  Access Servers:  {', '.join(asrvs)}\n")
                out.write(f"  Client IPs seen: {', '.join(aips) if aips else 'n/a'}\n")
                out.write(f"\n  Outage stats:\n")
                out.write(stats_block(atimes))
                out.write(f"\n  Total downtime stats:\n")
                out.write(stats_block(atotal))
                out.write(f"\n  Ping stats:\n")
                out.write(stats_block(apings))
                out.write("\n  Per access server:\n")
                for srv in asrvs:
                    srows  = [r for r in arows if r['server'] == srv]
                    stimes = [r['outage_ms'] for r in srows]
                    spings = [r['ping_ms']   for r in srows]
                    out.write(pair_row(srv, stimes, indent="    "))
                    out.write(f"      avg ping on {srv}: {statistics.mean(spings):.2f} ms\n")
                if aspikes:
                    out.write(f"\n  Spikes >={athresh:.0f} ms:  {len(aspikes)} events\n")
                    for sp in sorted(aspikes, key=lambda x: x['outage_ms'], reverse=True):
                        out.write(event_header(sp, indent="    "))
                        write_trade_block(out, sp, indent="    ")
                else:
                    out.write(f"\n  No spikes above {athresh:.0f} ms.\n")

            # ----------------------------------------------------------------
            out.write(section("3. PER ACCESS SERVER STATS"))
            server_counts = Counter(r['server'] for r in all_events)
            for srv in sorted(server_counts, key=lambda s: -server_counts[s]):
                srows  = [r for r in all_events if r['server'] == srv]
                stimes = [r['outage_ms'] for r in srows]
                spings = [r['ping_ms']   for r in srows]
                sauto  = sum(1 for r in srows if r['auto_triggered'])

                out.write(subsection(f"Server: {srv}  ({len(srows)} reconnects, {sauto} auto-switches)"))
                out.write(f"\n  Outage stats:\n")
                out.write(stats_block(stimes))
                out.write(f"\n  Ping stats:\n")
                out.write(stats_block(spings))
                buckets = Counter(round(p / 5) * 5 for p in spings)
                out.write("\n  Ping distribution (5 ms buckets):\n")
                for bucket in sorted(buckets):
                    bar = "#" * buckets[bucket]
                    out.write(f"    {bucket:>6.0f} ms  {buckets[bucket]:>4}  {bar}\n")

            # ----------------------------------------------------------------
            out.write(section("4. AUTO-SWITCHES vs UNEXPECTED DROPS"))
            out.write(f"  Total events:      {len(all_events)}\n")
            out.write(f"  Auto-switches:     {len(auto_events)}\n")
            out.write(f"  Unexpected drops:  {len(manual_events)}\n\n")
            if auto_events:
                at = [r['outage_ms'] for r in auto_events]
                out.write(f"  Auto-switch outage stats:\n")
                out.write(stats_block(at))
            if manual_events:
                mt = [r['outage_ms'] for r in manual_events]
                out.write(f"\n  Unexpected drop outage stats:\n")
                out.write(stats_block(mt))
            if multi_auth_events:
                out.write(f"\n  Multi-auth events (re-authorized >1x before sync confirmed):\n")
                for ev in multi_auth_events:
                    out.write(f"    [{ev['auth_count']}x auth] lost={ev['lost_ts']}  "
                              f"first_auth={ev['first_auth_ts']} ({ev['first_auth_server']})  "
                              f"final_auth={ev['auth_ts']} ({ev['server']})  "
                              f"outage={ev['outage_ms']:.0f} ms\n")

            # ----------------------------------------------------------------
            out.write(section("5. GLOBAL TOTALS"))
            out.write("\n  Outage stats (lost → auth):\n")
            out.write(stats_block(all_outages))
            out.write("\n  Sync delta stats (auth → synchronized):\n")
            out.write(stats_block(all_sync_deltas))
            out.write("\n  Total downtime stats (lost → synchronized):\n")
            out.write(stats_block(all_total_down))
            out.write("\n  Ping stats:\n")
            out.write(stats_block(all_pings))
            if all_events:
                worst = max(all_events, key=lambda x: x['total_down_ms'])
                best  = min(all_events, key=lambda x: x['outage_ms'])
                out.write(f"\n  Longest total downtime: {worst['total_down_ms']:.0f} ms  "
                          f"({ms_to_hms(worst['total_down_ms'])})  "
                          f"lost={worst['lost_ts']}  srv={worst['server']}  acct={worst['account']}\n")
                out.write(f"  Fastest reconnect:      {best['outage_ms']:.0f} ms  "
                          f"lost={best['lost_ts']}  auth={best['auth_ts']}  "
                          f"srv={best['server']}  acct={best['account']}\n")
            builds = sorted(set(r['build'] for r in all_events))
            out.write(f"\n  Build numbers seen: {', '.join(map(str, builds))}\n")

            # ----------------------------------------------------------------
            out.write(section(f"6. SPIKE ANALYSIS  threshold={spike_thresh:.0f} ms"))
            pct = 100 * len(spikes_all) / len(all_events)
            out.write(f"  Total spikes:  {len(spikes_all)} of {len(all_events)}  ({pct:.1f}%)\n\n")
            if spikes_all:
                for sp in sorted(spikes_all, key=lambda x: x['outage_ms'], reverse=True):
                    out.write(event_header(sp, indent="  "))
                    write_trade_block(out, sp, indent="  ")
                    out.write("\n")

                out.write(subsection("Spikes per access server"))
                for srv in all_servers:
                    row = spike_row(srv,
                                    [r for r in all_events if r['server'] == srv],
                                    [r for r in spikes_all if r['server'] == srv])
                    if row: out.write(row)

                out.write(subsection("Spikes per account"))
                for acct in all_accounts:
                    row = spike_row(f"Account {acct}",
                                    [r for r in all_events  if r['account'] == acct],
                                    [r for r in spikes_all  if r['account'] == acct])
                    if row: out.write(row)

            # ----------------------------------------------------------------
            out.write(section("7. HOURLY BREAKDOWN  (Server Time)"))
            out.write(f"  {'Hour':>5}  {'Count':>6}  {'Auto':>5}  "
                      f"{'Min ms':>10}  {'Max ms':>10}  {'Avg ms':>10}  "
                      f"{'Spikes':>7}  {'Avg ping':>9}  {'Aff':>5}\n")
            out.write("  " + "-" * 82 + "\n")
            for hour in range(24):
                hrows = [r for r in all_events if r['hour'] == hour]
                if not hrows: continue
                htimes  = [r['outage_ms'] for r in hrows]
                hpings  = [r['ping_ms']   for r in hrows]
                hspikes = sum(1 for t in htimes if t >= spike_thresh)
                hauto   = sum(1 for r in hrows if r['auto_triggered'])
                haff    = sum(len(r['affected_trades']) for r in hrows)
                out.write(
                    f"  {hour:02d}:xx  {len(hrows):>6}  {hauto:>5}  "
                    f"{min(htimes):>10.0f}  {max(htimes):>10.0f}  "
                    f"{statistics.mean(htimes):>10.0f}  {hspikes:>7}  "
                    f"{statistics.mean(hpings):>9.2f}  {haff:>5}\n"
                )
            spike_hours = sorted(set(r['hour'] for r in spikes_all)) if spikes_all else []
            if spike_hours:
                out.write(f"\n  Hours with spikes: {', '.join(f'{h:02d}:xx' for h in spike_hours)}\n")

            # ----------------------------------------------------------------
            out.write(section("8. PER-DATE BREAKDOWN"))
            date_counts = Counter(r['date'] for r in all_events if r['date'])
            out.write(f"  {'Date':<14}  {'Events':>7}  {'Auto':>5}  {'Drops':>5}  "
                      f"{'Avg ms':>10}  {'Max ms':>10}  {'Spikes':>7}  {'Aff':>5}\n")
            out.write("  " + "-" * 72 + "\n")
            for date in sorted(date_counts):
                drows  = [r for r in all_events if r['date'] == date]
                dtimes = [r['outage_ms'] for r in drows]
                dauto  = sum(1 for r in drows if r['auto_triggered'])
                dsp    = sum(1 for t in dtimes if t >= spike_thresh)
                daff   = sum(len(r['affected_trades']) for r in drows)
                out.write(
                    f"  {date:<14}  {len(drows):>7}  {dauto:>5}  {len(drows)-dauto:>5}  "
                    f"{statistics.mean(dtimes):>10.0f}  {max(dtimes):>10.0f}  {dsp:>7}  {daff:>5}\n"
                )

            # ----------------------------------------------------------------
            out.write(section("9. RECURRING DISCONNECT TIMES"))
            out.write("  Times (HH:MM) that occur on 3 or more separate dates — likely scheduled\n"
                      "  maintenance windows, broker rollover, or automated scanning cycles.\n\n")
            time_dates = defaultdict(set)
            for r in all_events:
                t    = r['lost_ts'].replace(':', '')
                hhmm = f"{t[0:2]}:{t[2:4]}"
                time_dates[hhmm].add(r['date'])
            recurring = sorted(
                [(hhmm, dates) for hhmm, dates in time_dates.items() if len(dates) >= 3],
                key=lambda x: -len(x[1])
            )
            if recurring:
                out.write(f"  {'Time':>6}  {'Days':>5}  Dates\n")
                out.write("  " + "-" * 58 + "\n")
                for hhmm, dates in recurring:
                    out.write(f"  {hhmm}  {len(dates):>5}  {', '.join(sorted(dates)[:10])}"
                              f"{'...' if len(dates) > 10 else ''}\n")
            else:
                out.write("  No strongly recurring times found (threshold: 3+ dates).\n")
            out.write("=" * 64 + "\n")

    # ---------------------------------------------------------------------------
    # OUTPUT 3: connection_report.txt  (quick-glance)
    # ---------------------------------------------------------------------------
    report_path = os.path.join(output_dir, "connection_report.txt")
    with open(report_path, 'w', encoding='utf-8') as out:
        out.write(section("CONNECTION QUICK-GLANCE REPORT"))
        out.write(f"  Generated:          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write(f"  Version:            {__version__}\n")
        out.write(f"  Source:             {source_dir}\n")
        out.write(f"  Spike threshold:    {spike_thresh:.0f} ms\n")
        out.write(f"  Total events:       {len(all_events)}\n")
        out.write(f"    Unexpected drops: {len(manual_events)}\n")
        out.write(f"    Auto-switches:    {len(auto_events)}\n")
        out.write(f"  Total spikes:       {len(spikes_all)}  "
                  f"({100*len(spikes_all)/max(len(all_events),1):.1f}%)\n")
        out.write(f"  Trades in windows:  {total_affected}\n")
        out.write(f"  Post-fills found:   {total_post}\n")

        if not all_events:
            out.write("No connection events found.\n")
        else:
            out.write(subsection("TOP 10 WORST OUTAGES (total downtime: lost → synced)"))
            top10 = sorted(all_events, key=lambda x: x['total_down_ms'], reverse=True)[:10]
            for i, sp in enumerate(top10, 1):
                kind = "AUTO-SW" if sp['auto_triggered'] else "DROP"
                out.write(
                    f"  {i:>2}. [{kind}] {sp['lost_ts']}→{sp['auth_ts']}  "
                    f"outage={sp['outage_ms']:.0f} ms  sync_delta={sp['sync_delta_ms']:.0f} ms  "
                    f"total={sp['total_down_ms']:.0f} ms ({ms_to_hms(sp['total_down_ms'])})  "
                    f"srv={sp['server']}  ping={sp['ping_ms']:.0f} ms  acct={sp['account']}\n"
                )
                write_trade_block(out, sp, indent="      ")

            out.write(subsection("ACCESS SERVER USAGE & PING"))
            out.write(f"  {'Server':<14}  {'Reconnects':>10}  {'%':>6}  {'Auto':>5}  "
                      f"{'Ping min':>9}  {'Ping avg':>9}  {'Ping max':>9}  {'Ping med':>9}\n")
            out.write("  " + "-" * 78 + "\n")
            for srv in sorted(all_servers):
                srows = [r for r in all_events if r['server'] == srv]
                pings = [r['ping_ms'] for r in srows]
                sauto = sum(1 for r in srows if r['auto_triggered'])
                pct_s = 100 * len(srows) / len(all_events)
                out.write(
                    f"  {srv:<14}  {len(srows):>10}  {pct_s:>6.1f}%  {sauto:>5}  "
                    f"{min(pings):>9.2f}  {statistics.mean(pings):>9.2f}  "
                    f"{max(pings):>9.2f}  {statistics.median(pings):>9.2f}\n"
                )

            out.write(subsection("OUTAGES PER ACCOUNT"))
            for acct in all_accounts:
                arows  = [r for r in all_events if r['account'] == acct]
                atimes = [r['outage_ms'] for r in arows]
                haff   = sum(len(r['affected_trades']) for r in arows)
                hpost  = sum(len(r['post_exec_trades']) for r in arows)
                aauto  = sum(1 for r in arows if r['auto_triggered'])
                aips   = sorted(set(r['client_ip'] for r in arows if r['client_ip']))
                out.write(
                    f"  Account {acct:<12}  {len(arows):>5} events  "
                    f"({aauto} auto-sw / {len(arows)-aauto} drops)  "
                    f"avg={statistics.mean(atimes):>7.0f} ms  "
                    f"med={statistics.median(atimes):>7.0f} ms  "
                    f"max={max(atimes):>7.0f} ms  "
                    f"aff={haff}  post={hpost}\n"
                )
                if aips:
                    out.write(f"    Client IPs: {', '.join(aips)}\n")

            out.write(subsection("TRADES AFFECTED BY OUTAGES"))
            any_trade = False
            for ev in sorted(all_events, key=lambda x: x['lost_ms']):
                if ev['affected_trades'] or ev['post_exec_trades']:
                    any_trade = True
                    kind = "AUTO-SW" if ev['auto_triggered'] else "DROP"
                    out.write(
                        f"  [{kind}] {ev['lost_ts']} -> {ev['auth_ts']}  "
                        f"({ev['outage_ms']:.0f} ms)  srv={ev['server']}  acct={ev['account']}\n"
                    )
                    write_trade_block(out, ev, indent="    ")
                    out.write("\n")
            if not any_trade:
                out.write("  No trade activity detected during any outage window.\n")

            out.write(subsection("HOURLY OUTAGE HEATMAP  (Server Time)"))
            out.write("  Hour     Count  Auto  Bar\n")
            out.write("  " + "-" * 54 + "\n")
            hour_counts = [(sum(1 for r in all_events if r['hour'] == h),
                            sum(1 for r in all_events if r['hour'] == h and r['auto_triggered']))
                           for h in range(24)]
            max_h = max(c for c, _ in hour_counts) if any(c for c, _ in hour_counts) else 1
            for hour, (count, auto) in enumerate(hour_counts):
                if count == 0: continue
                bar = "#" * int(count / max_h * 35)
                out.write(f"  {hour:02d}:xx  {count:>5}  {auto:>4}  {bar}\n")

            day_counts = Counter(r['file'].replace('.log', '') for r in spikes_all)
            if day_counts:
                out.write(subsection("SPIKE DATES  (worst days)"))
                max_d = max(day_counts.values())
                for date, count in sorted(day_counts.items(), key=lambda x: -x[1])[:20]:
                    bar = "#" * int(count / max_d * 30)
                    out.write(f"  {date:<20}  {count:>4}  {bar}\n")

            out.write(subsection("FULL SPIKE LIST  (worst first)"))
            for sp in sorted(spikes_all, key=lambda x: x['outage_ms'], reverse=True):
                out.write(event_header(sp, indent="  "))
                write_trade_block(out, sp, indent="    ")
                out.write("\n")

        out.write("=" * 64 + "\n")

    # ---------------------------------------------------------------------------
    print(f"\n  written to:")
    print(f"    {events_path}")
    print(f"    {summary_path}")
    print(f"    {report_path}")
    if all_outages:
        print(
            f"\n  {len(all_events)} events  ({len(auto_events)} auto-sw / {len(manual_events)} drops)"
            f" | {len(terminals)} terminals | {len(all_accounts)} accounts | {len(all_servers)} servers\n"
            f"  outage  min={min(all_outages):.0f} ms  max={max(all_outages):.0f} ms  "
            f"avg={statistics.mean(all_outages):.0f} ms  med={statistics.median(all_outages):.0f} ms\n"
            f"  total↓  min={min(all_total_down):.0f} ms  max={max(all_total_down):.0f} ms  "
            f"avg={statistics.mean(all_total_down):.0f} ms\n"
            f"  ping    min={min(all_pings):.2f} ms  max={max(all_pings):.2f} ms  "
            f"avg={statistics.mean(all_pings):.2f} ms\n"
            f"  spikes >={spike_thresh:.0f} ms: {len(spikes_all)}\n"
            f"  trades in outage windows: {total_affected}  post-fills: {total_post}"
        )
    else:
        print("  No matching connection events found.")


if __name__ == '__main__':
    main()
