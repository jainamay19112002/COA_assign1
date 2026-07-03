//-----------------------------------------VERIFICATION MODULE-------------------------------------------

//what is this module?
/*The verification module acts as a built-in checker that compares the computed hash against 
the expected hash and generates a binary verified flag */


module verify_spn(
    input wire [7:0] plaintext,       // Original input text
    input wire [7:0] expected_hash,   // Hash received/stored for verification
    output wire [7:0] ciphertext,     // Ciphertext 
    output wire [7:0] hash_val,       // Hash computed
    output wire verified              // 1 if hashes match, else 0
);

    //--------------------Internal wires--------------------
    wire [7:0] enc_out;
    wire [7:0] xor_val;
    wire [7:0] shifted_val;

    //--------------------Encryption------------------------
    encrypt_spn enc_inst (
        .data_input(plaintext),
        .data_output(enc_out),
        .s_box_val(),          
        .perm_val()           
    );

    //--------------------Hashing---------------------------
    hash_spn hash_inst (
        .data_in(enc_out),
        .hash_out(hash_val),
        .xor_val(xor_val),
        .shifted_val(shifted_val)
    );

    //--------------------Verification----------------------
    assign ciphertext = enc_out;
    assign verified = (hash_val == expected_hash);

endmodule
