
# Change Log
All notable changes to this project will be documented in this file.
 
The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).
 
## [0.7.0] - 2024-12-3
 
### Added
### Changed
#### Circuit Builds
#### Artifacts
- **Circuit sizes:**
    - `plaintext_authentication_1024b`: 
        - non-linear constaints: `383,102`
        - R1CS file: `123.4MB`
        - Graph file: `19.9MB`
    - `http_verification_1024b`: 
        - non-linear constaints: `121,376`
        - R1CS file: `80.7MB`
        - Graph file: `4.4MB`
        - **WARNING:** Extremely slow build with `--O2` flag. Need to investigate.
    - `json_extraction_1024b`: 
        - non-linear constaints: `452,683`
        - R1CS file: `90.3MB`
        - Graph file: `13.2MB`
    - **Total size:** `243.7MB`
- **Circuit param file sizes (SNARK):**
    - `aux_params`: `62.2MB`
    - `prover_key`: `50.3MB`
    - `verifier_key`: `415.3MB`         

### Notes

--- 

## [0.6.0] - 2024-12-3
 
### Added

### Changed
#### Circuit Builds
- Removed `512b` build path
- Removed `aes_gctr_nivc_*b.circom` from build

#### Artifacts
- Adjusted circuit names:
    - `aes_gctr_nivc` and `chacha20-nivc` replaced with a more suitable name: `plaintext_authentication`
        - Runs with `512b` per fold
    - `http_nivc` replaced with more suitable name: `http_verification`

### Notes
- **Total circuits:** 5
- **Circuit sizes:**
    - `plaintext_authentication_1024b` 
        - non-linear constraints: `365,484`
        - linear-constraints: `40,463`
        - Theoretical storage size: `(40,463 + 365,484) * 3 * 32 bytes = 38,971,912 bytes ≈ 39 MB`
        - R1CS file: `121.3MB`
        - Graph file: `13.1MB`
        - **WARNINGS:** Yes. Run `circomkit compile plaintext_authentication_1024b`
    - `http_verification_1024b`: 
        - non-linear constaints: `546,895` **(WARNING: greater than `2^19 == 524,288`)**
        - linear-constraints: `543,804` 
        - Theoretical storage size: `(546,895 + 543,804) * 3 * 32 bytes = 104,707,104 bytes ≈ 105 MB`
        - R1CS file: `246.4MB`
        - Graph file: `16.5MB`
        - **WARNINGS:** Yes. Run `circomkit compile http_verification_1024b`
    - `json_mask_object_1024b`: 
        - non-linear constraints: `550,001` **(WARNING: greater than `2^20 == 524,288`)**
        - linear-constraints: `316,205`
        - Theoretical storage size: `(550,001 + 316,205) * 3 * 32 bytes = 83,155,776 bytes ≈ 83 MB`
        - R1CS file: `109MB`
        - Graph file: `9.3MB`
        - **WARNINGS:** Yes. Run `circomkit compile json_mask_object_1024b`
    - `json_mask_array_index_1024b`: 
        - non-linear constraints: `295,146`
        - linear-constraints: `194,082`
        - Theoretical storage size: `(295,146 + 194,082) * 3 * 32 bytes = 46,966,080 bytes ≈ 47 MB`
        - R1CS file: `67.4MB`
        - Graph file: `7.4MB`
        - **WARNINGS:** Yes. Run `circomkit compile json_mask_array_index_1024b`
    - `json_extract_value_1024b`: 
        - non-linear constraints == `32,039`
        - linear-constraints: `18,644`
        - Theoretical storage size: `(32,039 + 18,644) * 3 * 32 bytes = 4,865,568 bytes ≈ 4.8 MB`
        - R1CS file: `11.1MB`
        - Graph file: `949KB`
- **Estimated expanded R1CS base memory requirements:** `2^{20} * 32 * 5 ~ 168MB`$
- **Circuit param file sizes (SNARK):**
    - `aux_params`: `115.1MB`
    - `prover_key`: `100.7MB`
    - `verifier_key`: `780.3MB`
- **Circuit param file sizes (ppSNARK):**
    - `aux_params`: `836MB` **(WARNING: THIS IS LARGE)**
    - `prover_key`: `5.86GB` **(WARNING: THIS IS EXTREMELY LARGE!!!)**
    - `verifier_key`: `16.8MB`

