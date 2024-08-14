# SKA CSP - PSR Packet Analyser

https://docs.google.com/document/d/1LpEoxHtj0BMfzKg3FEBXUUra2S6qtCVfocQqX1uXkHE/edit#heading=h.hx5ha7v7z3e7
https://gitlab.com/ska-telescope/low-cbf/ska-low-cbf-integration

## How to Use

Name your network capture `pss.pcap` (or change the value `payloads = extract_udp_payloads("pss.pcap")` on line 127 to whatever you want) and make sure it's in the same directory as the script `psr-analyzer.py`. Then run the script with `python psr-analyzer.py`, and it outputs a nice looking table, or an error.

### Arguments

`--plain` or `--notable` output the plain output, without the table formatting.
If you want to output the data to a file, just run it with `> file`. e.g.:
```bash
python psr-analyzer.py --plain > analysis.txt
```
