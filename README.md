# PrivScout

**Documentation:** English | [Español](docs/README.es.md)

PrivScout is a command-line tool for prioritizing Linux privilege-escalation
enumeration. It reads text files containing SUID paths, `sudo -l` rules, and
file capabilities, filters common noise, and brings the findings that deserve
manual review to the top.

Its primary source of documented techniques is **GTFOBins**. PrivScout adds
context-aware matching, explainable scoring, common-package baselines, and
offline correlations with third-party software, Exploit-DB, and CVE data.

PrivScout does not exploit the system, execute discovered binaries, or connect
to the target. Use it only on systems you own or are authorized to test.

## How it works

1. Reads any `.txt` file or standard input.
2. Automatically detects SUID, sudo, and capability entries.
3. Normalizes names and groups repeated observations.
4. Reduces noise from expected system binaries and capability combinations.
5. Queries the offline GTFOBins dataset for the detected execution context.
6. Adds signals such as unusual paths, sudo arguments, high-impact
   capabilities, and possible third-party products.
7. Assigns a score from 0 to 100 and presents actions for manual validation.

A GTFOBins match means that a technique is documented for that context. It does
not prove that the target is vulnerable.

## Requirements

- Python 3.11 or newer.
- Internet access to install dependencies and run `privscout update`.
- Normal analysis works offline.

## Installation

### Linux: command available everywhere

For a command-line application, the recommended option is
[pipx](https://pipx.pypa.io/stable/). It keeps PrivScout isolated from the
system Python while exposing `privscout` on your user `PATH`:

```bash
# Debian, Ubuntu, Kali, and derivatives
sudo apt install pipx
pipx ensurepath

# Run this from the cloned PrivScout directory
pipx install .
```

Open a new terminal after `pipx ensurepath`. You can then run `privscout` from
any directory without activating an environment.

### Windows PowerShell

```powershell
py -m pip install --user pipx
py -m pipx ensurepath

# Run this from the cloned PrivScout directory
pipx install .
```

Open a new PowerShell window before using the command.

Verify the installation:

```console
privscout version
privscout --help
```

### Update the offline database

After installation, it is recommended to download the latest GTFOBins,
Exploit-DB, and relevant CVE data:

```console
privscout update
```

This command requires Internet access. PrivScout includes an initial database,
so updating is recommended but not required for the first analysis. Once the
update finishes, normal analysis remains offline. Use `privscout update --json`
for a machine-readable update report.

## Usage

PrivScout does not require a special input directory. Pass the path to any text
file:

```console
privscout analyze enumeration.txt
privscout analyze C:\path\to\results.txt
```

`analyze` detects each input type automatically. You can also select a specific
source:

```console
privscout suid suids.txt
privscout sudo sudo.txt
privscout caps capabilities.txt
```

Use `-` to read from standard input:

```bash
cat enumeration.txt | privscout analyze -
```

```powershell
Get-Content .\enumeration.txt | privscout analyze -
```

## Collecting input

On the authorized Linux system, collect the three main sources with:

```bash
find / -perm -4000 -type f 2>/dev/null
sudo -l
getcap -r / 2>/dev/null
```

Save each output separately or combine them using section headers:

```text
=== SUID ===
/usr/bin/passwd
/usr/local/bin/custom-helper

=== SUDO ===
(root) NOPASSWD: /usr/bin/systemctl restart demo.service

=== CAPABILITIES ===
/usr/bin/ping cap_net_raw=ep
/usr/bin/python3.11 cap_setuid=ep
```

## Useful options

- `--lang es`: display output in Spanish.
- `--explain`: show the reasons behind each score.
- `--show-all`: include common and low-priority entries.
- `--min-score N`: set the minimum score to display.
- `--json`: produce structured output.
- `--no-color`: disable ANSI colors.
- `--verbose`: show parser and dataset diagnostics.

```console
privscout analyze enumeration.txt --explain
privscout analyze enumeration.txt --min-score 70 --no-color
privscout sudo sudo.txt --json > report.json
privscout analyze enumeration.txt --lang es
```

## Understanding the results

| Score | Priority |
| ---: | --- |
| 90–100 | Critical |
| 70–89 | High |
| 40–69 | Medium |
| 20–39 | Low |
| 0–19 | Informational |

By default, PrivScout displays findings with a score of 40 or higher. Results
are separated into GTFOBins correlations, offline third-party software leads,
and findings that require manual review.

Displayed actions and commands are suggestions for validation. PrivScout never
executes them.

## License

PrivScout is released under the MIT License. See [LICENSE](LICENSE).
