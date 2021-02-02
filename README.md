# Dynamo: Tool & Results
Please, see Results directory for permission mappings of Android 6 and 10.

# Content Provider Fuzzing
## Working configuration
- Ubuntu 20.04.1 LTS (Google Cloud Compute Engine)
- Python 3.8

## Setup
1. Copy `cp_fuzz_config.json.example` to `cp_fuzz_config.json` and update the config file.
2. Run `pip install -r requirements.txt`
3. Run `main.py --fuzz-content-providers`
4. Check `out/cp_fuzzing_results/yyyy-mm-dd-hh-mm-ss/*`