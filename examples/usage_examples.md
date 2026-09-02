# Log Analyzer — usage examples

Run against the bundled sample (`examples/sample.log`) or pipe live logs in.
**Defensive / educational use** — analyze logs you are authorized to process.

## Basic analysis

```bash
python log_analyzer.py examples/sample.log
```

## Only high / critical findings (quiet, no color)

```bash
python log_analyzer.py examples/sample.log --min-severity 3 --no-color
```

## Machine-readable JSON

```bash
python log_analyzer.py examples/sample.log --json
```

## Pipe live logs from a server

```bash
# Live tail of an nginx access log.
tail -f /var/log/nginx/access.log | python log_analyzer.py --stdin

# Or feed via redirect.
python log_analyzer.py < /var/log/apache2/access.log
```

## Tune detection

```bash
# Broader brute-force window: 10 failed attempts in 600s.
python log_analyzer.py examples/sample.log --window 600 --threshold 10

# Higher port-scan sensitivity: 12 distinct ports.
python log_analyzer.py examples/sample.log --scan-ports 12

# Catch request bursts earlier.
python log_analyzer.py examples/sample.log --burst-min 20 --burst-factor 3
```

## Source controls

```bash
# Ignore a known-benign monitoring IP.
python log_analyzer.py examples/sample.log --noise-ip 10.0.0.5

# Block a specific source.
python log_analyzer.py examples/sample.log --blacklist 203.0.113.66
```

## Quiet / scripting mode

```bash
python log_analyzer.py examples/sample.log --quiet --no-color
echo $?   # 0 = clean, 1 = findings detected, 2 = usage error
```

## Multiple files

```bash
python log_analyzer.py access.log auth.log error.log --min-severity 2
```
