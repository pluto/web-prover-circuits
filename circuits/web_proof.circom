pragma circom 2.1.9;

include "aes-gcm/nivc/aes-gctr-nivc.circom";
include "http/nivc/parse_and_lock_start_line.circom";
include "http/nivc/lock_header.circom";
include "http/nivc/body_mask.circom";
include "json/nivc/parse.circom";
include "json/nivc/masker.circom";
include "json/nivc/masker.circom";
include "json/nivc/extractor.circom";

// AES -> HTTP Parse -> http lock header -> http body mask -> json parse -> json_mask_object/json_mask_array -> extract value
// DATA_BYTES = length of block * 2 + 4
// e.g. 36 = 16 * 2 + 4 for a single block
template WEPPROOF(
    DATA_BYTES, 
    MAX_STACK_HEIGHT, 
    MAX_BEGINNING_LENGTH, 
    MAX_MIDDLE_LENGTH, 
    MAX_FINAL_LENGTH, 
    MAX_HEADER_NAME_LENGTH, 
    MAX_HEADER_VALUE_LENGTH, 
    MAX_KEY_LENGTH, 
    MAX_VALUE_LENGTH) { 

    var TOTAL_BYTES_ACROSS_NIVC = DATA_BYTES * 2 + 4;
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC]; 
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];

    // AES
    signal input key[16];
    signal input iv[12];
    signal input aad[16];
    signal input plainText[16];
    component aes_gctr_nivc = AESGCTRFOLD(DATA_BYTES);
    aes_gctr_nivc.key <== key;
    aes_gctr_nivc.iv <== iv;
    aes_gctr_nivc.aad <== aad;
    aes_gctr_nivc.plainText <== plainText;
    aes_gctr_nivc.step_in <== step_in;

    // Parse and lock 
    component http_parse = ParseAndLockStartLine(DATA_BYTES, 
            MAX_STACK_HEIGHT, 
            MAX_BEGINNING_LENGTH, 
            MAX_MIDDLE_LENGTH, 
            MAX_FINAL_LENGTH);
    
    signal input beginning[MAX_BEGINNING_LENGTH];
    signal input beginning_length;
    signal input middle[MAX_MIDDLE_LENGTH];
    signal input middle_length;
    signal input final[MAX_FINAL_LENGTH];
    signal input final_length;

    http_parse.step_in <== aes_gctr_nivc.step_out;
    http_parse.beginning <== beginning;
    http_parse.beginning_length <== beginning_length;
    http_parse.middle <== middle;
    http_parse.middle_length <== middle_length;
    http_parse.final <== final;
    http_parse.final_length <== final_length;

    // Lock header
    component http_lock_header = LockHeader(DATA_BYTES, 
            MAX_STACK_HEIGHT, 
            MAX_HEADER_NAME_LENGTH, 
            MAX_HEADER_VALUE_LENGTH);

    signal input header[MAX_HEADER_NAME_LENGTH];
    signal input headerNameLength;
    signal input value[MAX_HEADER_VALUE_LENGTH];
    signal input headerValueLength;

    http_lock_header.step_in <== http_parse.step_out;
    http_lock_header.header <== header;
    http_lock_header.headerNameLength <== headerNameLength;
    http_lock_header.value <== value;
    http_lock_header.headerValueLength <== headerValueLength;

    // HTTP body mask
    component http_body_mask = HTTPMaskBodyNIVC(DATA_BYTES, MAX_STACK_HEIGHT);
    http_body_mask.step_in <== http_lock_header.step_out;

    // JSON parse
    component json_parse = JsonParseNIVC(DATA_BYTES, MAX_STACK_HEIGHT);
    json_parse.step_in <== http_body_mask.step_out;

    // Note: picked Array over object for now 
    // TODO(WJ 2024-11-01): add conditional logic via a mux
    // template JsonMaskObjectNIVC(DATA_BYTES, MAX_STACK_HEIGHT, MAX_KEY_LENGTH)
    // component json_mask_object = JsonMaskObjectNIVC(DATA_BYTES, MAX_STACK_HEIGHT, MAX_KEY_LENGTH);

    // JSON array
    component json_mask_array = JsonMaskArrayIndexNIVC(DATA_BYTES, MAX_STACK_HEIGHT);
    json_mask_array.step_in <== json_parse.step_out;

    // Final Extraction
    component extract_value = MaskExtractFinal(DATA_BYTES, MAX_STACK_HEIGHT, MAX_VALUE_LENGTH);
}

/// Note, DATA_BYTES > MAX_BEGINNING_LENGTH and MAX_MIDDLE_LENGTH and MAX_FINAL_LENGTH
component main = WEPPROOF(
    64, // DATA_BYTES
    5,  // MAX_STACK_HEIGHT
    10, // MAX_BEGINNING_LENGTH
    50, // MAX_MIDDLE_LENGTH
    10, // MAX_FINAL_LENGTH
    12, // MAX_HEADER_NAME_LENGTH
    16,  // MAX_HEADER_VALUE_LENGTH
    8,  // MAX_KEY_LENGTH
    16  // MAX_VALUE_LENGTH
    );

    // const MAX_STACK_HEIGHT = 5;
    // const PER_ITERATION_DATA_LENGTH = MAX_STACK_HEIGHT * 2 + 2;
    // const TOTAL_BYTES_ACROSS_NIVC = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1) + 1;

    // const MAX_BEGINNING_LENGTH = 10;
    // const MAX_MIDDLE_LENGTH = 50;
    // const MAX_FINAL_LENGTH = 10;