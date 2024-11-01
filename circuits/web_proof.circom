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
template WEPPROOF(DATA_BYTES) { 

    // AES inputs
    signal input key[16];
    signal input iv[12];
    signal input aad[16];
    signal input plainText[16];
    // step_in[0..INPUT_LEN] => accumulate plaintext blocks
    // step_in[INPUT_LEN..INPUT_LEN*2]  => accumulate ciphertext blocks
    // step_in[INPUT_LEN*2..INPUT_LEN*2+4]  => accumulate counter
    signal input step_in[DATA_BYTES]; 
    signal output step_out[DATA_BYTES];

    component aes_gctr_nivc = AESGCTRFOLD(DATA_BYTES);
    aes_gctr_nivc.key <== key;
    aes_gctr_nivc.iv <== iv;
    aes_gctr_nivc.aad <== aad;
    aes_gctr_nivc.plainText <== plainText;
    aes_gctr_nivc.step_in <== step_in;

    // Parse and lock start line inputs
    signal input beginning;
    signal input beginning_length;
    signal input middle;
    signal input middle_length;
    signal input final;
    signal input final_length;
    
    // ParseAndLockStartLine(DATA_BYTES, MAX_STACK_HEIGHT, MAX_BEGINNING_LENGTH, MAX_MIDDLE_LENGTH, MAX_FINAL_LENGTH)
    component http_parse = ParseAndLockStartLine(DATA_BYTES, 16, 10, 3, 2);

    http_parse.step_in <== aes_gctr_nivc.step_out;
    http_parse.beginning <== beginning;
    http_parse.beginning_length <== beginning_length;
    http_parse.middle <== middle;
    http_parse.middle_length <== middle_length;
    http_parse.final <== final;
    http_parse.final_length <== final_length;

    // template LockHeader(DATA_BYTES, MAX_STACK_HEIGHT, MAX_HEADER_NAME_LENGTH, MAX_HEADER_VALUE_LENGTH)
    component http_lock_header = LockHeader(DATA_BYTES, 16, 12, 16);


    signal input header;
    signal input headerNameLength;
    signal input value;
    signal input headerValueLength;

    http_lock_header.step_in <== http_parse.step_out;
    http_lock_header.header <== header;
    http_lock_header.headerNameLength <== headerNameLength;
    http_lock_header.value <== value;
    http_lock_header.headerValueLength <== headerValueLength;

    // template HTTPMaskBodyNIVC(DATA_BYTES, MAX_STACK_HEIGHT)
    component http_body_mask = HTTPMaskBodyNIVC(DATA_BYTES, 16);

    http_body_mask.step_in <== http_lock_header.step_out;

    // JsonParseNIVC(DATA_BYTES, MAX_STACK_HEIGHT)
    component json_parse = JsonParseNIVC(DATA_BYTES, 16);

    json_parse.step_in <== http_body_mask.step_out;

    // // template JsonMaskObjectNIVC(DATA_BYTES, MAX_STACK_HEIGHT, MAX_KEY_LENGTH)
    // component json_mask_object = JsonMaskObjectNIVC(DATA_BYTES, 16, 4);

    // template JsonMaskArrayIndexNIVC(DATA_BYTES, MAX_STACK_HEIGHT)
    component json_mask_array = JsonMaskArrayIndexNIVC(DATA_BYTES, 16);
    json_mask_array.step_in <== json_parse.step_out;

    // template MaskExtractFinal(DATA_BYTES, MAX_STACK_HEIGHT, MAX_VALUE_LENGTH)
    component extract_value = MaskExtractFinal(DATA_BYTES, 32, 32);
}
    
component main = WEPPROOF(36);

