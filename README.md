<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## Elastic Security Labs - nightMARE

This directory contains the night**MARE** (Malware Analysis & Reverse Engineering) library. nightMARE is a central module that will allow for an efficient and logical approach to automating various reverse engineering functions. 

The nightMARE library is born from the need to refactor our code base into reusable bricks. We want to concentrate logics and dependencies into a single library in order to speed up tool developement for members of the Elastic Security Labs team.

By open sourcing our library to the community we hope that it'll contribute to our battle against threats.

**Please note that this library is still young and under developement. Pull requests are welcome.**  
Example usage: https://www.elastic.co/security-labs/unpacking-icedid

## Malware modules

| Module                                | Description                              |
| ------------------------------------- | ---------------------------------------- |
| `nightmare.malware.blister`           | Implement BLISTER algorithms             |
| `nightmare.malware.ghostpulse`        | Implement GHOSTPULSE algorithms          |
| `nightmare.malware.deprecated.icedid` | Implement ICEDID algorithms (deprecated) |
| `nightmare.malware.latrodectus`       | Implement LATRODECTUS algorithms         |
| `nightmare.malware.lobshot`           | Implement LOBSHOT algorithms             |
| `nightmare.malware.lumma`             | Implement LUMMA algorithms               |
| `nightmare.malware.netwire`           | Implement NETWIRE algorithms             |
| `nightmare.malware.redlinestealer`    | Implement REDLINESTEALER algorithms      |
| `nightmare.malware.remcos`            | Implement REMCOS algorithms              |
| `nightmare.malware.smokeloader`       | Implement SMOKELOADER algorithms         |
| `nightmare.malware.stealc`            | Implement STEALC algorithms              |
| `nightmare.malware.warmcookie`        | Implement WARMCOOKIE algorithms          |
| `nightmare.malware.xorddos`           | Implement XORDDOS algorithms             |

## Requirements
- Python >= `3.10` is required.
- [Rizin **v0.8.1**](https://github.com/rizinorg/rizin/releases/tag/v0.8.1) must be installed and available in the system's PATH environment variable.

## Install
```bash
pip install nightmare-lib
```

or

```bash
git clone https://github.com/elastic/nightMARE
python -m pip install ./nightMARE
```

## Test
Download the corpus from [here](#not-yet) and place the archive in the `tests` folder to run the tests. **Warning: The archive contains malware; testing should be performed in a virtual machine for safety**.

```bash
py.test
```

## How to Contribute
Contributors must sign a Contributor License Agreement before contributing code to any Elastic repositories.
