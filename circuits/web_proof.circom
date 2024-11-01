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

    // template AESGCTRFOLD(DATA)
    component aes_gctr_nivc = AESGCTRFOLD(DATA_BYTES);

    // template ParseAndLockStartLine(DATA_BYTES, MAX_STACK_HEIGHT, MAX_BEGINNING_LENGTH, MAX_MIDDLE_LENGTH, MAX_FINAL_LENGTH)
    component http_parse = ParseAndLockStartLine(DATA_BYTES, 16, 8, 3, 2);

    // template LockHeader(DATA_BYTES, MAX_STACK_HEIGHT, MAX_HEADER_NAME_LENGTH, MAX_HEADER_VALUE_LENGTH)
    component http_lock_header = LockHeader(DATA_BYTES, 16, 12, 16);

    // template HTTPMaskBodyNIVC(DATA_BYTES, MAX_STACK_HEIGHT)
    component http_body_mask = HTTPMaskBodyNIVC(DATA_BYTES, 16);

    // JsonParseNIVC(DATA_BYTES, MAX_STACK_HEIGHT)
    component json_parse = JsonParseNIVC(DATA_BYTES, 16);
    // need logic to specif which json type
    // object or array

    // template JsonMaskObjectNIVC(DATA_BYTES, MAX_STACK_HEIGHT, MAX_KEY_LENGTH)
    component json_mask_object = JsonMaskObjectNIVC(DATA_BYTES, 16, 4);

    // template JsonMaskArrayIndexNIVC(DATA_BYTES, MAX_STACK_HEIGHT)
    component json_mask_array = JsonMaskArrayIndexNIVC(DATA_BYTES, 16);

    // template MaskExtractFinal(DATA_BYTES, MAX_STACK_HEIGHT, MAX_VALUE_LENGTH)
    component extract_value = MaskExtractFinal(DATA_BYTES, 32, 32);
}
    
component main = WEPPROOF(36);

