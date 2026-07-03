//---------------------------------------CREATING A TEST BENCH FOR 8-BIT SPN CIPHER--------------------------
//---------------------------------------ENCRYPT + DECRYPT + HASH + VERIFY-----------------------------------------

//what is test bench used for?
/* A test bench mainly works as a simulator for verifying the correctness and the functionality
 of the digital design. */

module tb_verify_spn;

    // Testbench signals
    reg  [7:0] plaintext;                    //8 bit input texxt
    reg  [7:0] expected_hash;                //expected hash value
    wire [7:0] ciphertext;                   //8 bit cipher text
    wire [7:0] hash_val;                     //hash value
    wire verified;

    // Instantiating the Design under test unit for testing
    verify_spn uut (
        .plaintext(plaintext),
        .expected_hash(expected_hash),
        .ciphertext(ciphertext),
        .hash_val(hash_val),
        .verified(verified)
    );

    // here we have created a function for running the test cases
    task run_test;
        input [7:0] pt;
        input [7:0] exp_hash;
        input  exp_result;
        reg [39:0] result_str;
        begin
            plaintext = pt;
            expected_hash = exp_hash;
            #10;  
            $display("| %8h | %10h | %8h | %13h | %8b |",
                     plaintext, ciphertext, hash_val, expected_hash, verified);
        end
    endtask

    // here we are generating the waveforms
    initial begin
    $dumpfile("wave.vcd");       // Name of the waveform file
    $dumpvars(0, tb_verify_spn); // Dump all signals in the testbench hierarchy
end


    // Test sequence
    integer i;
    reg [7:0] rand_in;

    initial begin
        // Table header format
        $display("---------------------------------------------------------------------------------------------");
        $display("| PLAINTEXT | CIPHERTEXT | HASH_VAL | EXPECTED_HASH | VERIFIED |");
        $display("---------------------------------------------------------------------------------------------");

        //The three fixed test cases
        run_test(8'h41, 8'hE0, 1);    //1st Test case
        run_test(8'hFF, 8'h84, 1);    //2nd Test case
        run_test(8'h27, 8'h30, 1);    //3rd Test case



        // Random test cases
        $display("---------------HERE WE ARE RUNNING SOME RANDOM TEST CASES ---------------");
        for (i=0;i<10;i=i+1) 
        begin
            rand_in = $random;   // random 8-bit value
            plaintext = rand_in;

            #10; 

            run_test(rand_in, hash_val, 1);
            run_test(rand_in, hash_val ^ 8'hFF, 0); 
        end

        $display("---------------------------------------------------------------------------------------------");
        $display("--------------- THANK YOU, ALL THE TEST CASES ARE COMPLETED........GOODBYE ---------------");
        $finish;
    end

endmodule
