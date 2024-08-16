# SKA CSP - PSR Packet Analyser

https://docs.google.com/document/d/1LpEoxHtj0BMfzKg3FEBXUUra2S6qtCVfocQqX1uXkHE/view

https://gitlab.com/ska-telescope/low-cbf/ska-low-cbf-integration

## How to Use

Name your network capture `pss.pcap` (or change the value `CAPTURE_FILE = "pss.pcap"` near the top of the file) and make sure it's in the same directory as the script `psr-analyser.py`. Then run the script with `python psr-analyser.py`.

### Arguments

`--plain` output the plain output, without the table formatting.

If you want to output the data to a file, just run it with `> file`. Example command:
```bash
python psr-analyser.py --plain > analysis.txt
```
