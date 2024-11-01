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
template WEPPROOF { 

    // template AESGCTRFOLD(INPUT_LEN)
    component aes_gctr_nivc = AESGCTRFOLD(48);

    // template ParseAndLockStartLine(DATA_BYTES, MAX_STACK_HEIGHT, MAX_BEGINNING_LENGTH, MAX_MIDDLE_LENGTH, MAX_FINAL_LENGTH)
    component http_parse = ParseAndLockStartLine(48, 16, 8, 3, 2);

    // template LockHeader(DATA_BYTES, MAX_STACK_HEIGHT, MAX_HEADER_NAME_LENGTH, MAX_HEADER_VALUE_LENGTH)
    component http_lock_header = LockHeader(48, 16, 12, 16);

    // template HTTPMaskBodyNIVC(DATA_BYTES, MAX_STACK_HEIGHT)
    component http_body_mask = HTTPMaskBodyNIVC(48, 16);

    // JsonParseNIVC(DATA_BYTES, MAX_STACK_HEIGHT)
    component json_parse = JsonParseNIVC(48, 16);
    // need logic to specif which json type
    // object or array


    component json_mask_object = JsonMaskObjectNIVC(48, 16, 4);
    component json_mask_array = JsonMaskArrayIndexNIVC(48, 16);
    // extract value
    component extract_value = MaskExtractFinal(49, 32, 32);
}
    
//  = AESGCTRFOLD(48);
component main = WEPPROOF();

