# Plan: Add Comprehensive Scan Profile

## Goal
Add a new scan profile called "comprehensive" that combines the best capabilities of existing profiles while providing a balanced, production-ready configuration.

## Tasks
1. **Define the COMPREHENSIVE profile** in `PROFILE_BY_ID` dictionary with:
   - Name: "comprehensive"
   - Description: Combines passive OSINT + full postings + deep brute-force + infrastructure audit
   - Wordlist slice: first 20,000 labels (balanced coverage)
   - Port matrix: extended (172 ports) for maximum coverage
   - Rate limits: moderate (stealth-friendly but thorough)
   - Additional flags: disable discovery (to speed up), enable all features

2. **Update profile table rendering** in `cmd_profiles` to include the new profile in the banner

3. **Verify the profile works** by running a test scan against a known domain

## Expected Outcome
A new scan profile "comprehensive" that users can select via `python main.py profiles --json` and use with `--profile comprehensive`

## Risks
- Profile name must be unique in PROFILE_BY_ID
- Must match naming conventions used by other profiles
- Default ordering may affect discoverability

## Implementation Steps
1. Locate `PROFILE_BY_ID` in `subsonar/core/profile.py`
2. Add new entry with appropriate values
3. Test the profile by running a scan
4. Verify the profile appears in the profiles list
