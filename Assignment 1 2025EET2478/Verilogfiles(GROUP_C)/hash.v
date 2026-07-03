                                         //HASHING MODULE//

//what is hashing here?
/* Hashing is one of the functions (typically mathematical) that helps to keep the sensitive information and
the data. It fixes a output using a hash function based on the input data. */


module hash_spn(
    input wire [7:0] data_in,                //takes the 8-bit Encrypted byte from the encrypt module
    output wire [7:0] hash_out,                 //final 8-bit Hash output
    output wire [7:0] xor_val,                  //intermediate debugging signal (result after xoring with the key)
    output wire [7:0] shifted_val               //intermediate debugging signal (result after the left shift)
);

parameter KEY=8'h5A;


//--------------------------XORing with the key----------------------------------------

function [7:0] xoring_withthe_key;
input [7:0]val;
xoring_withthe_key= val^KEY;
endfunction


//--------------------------Shifting left with 2 (moduluo 256)----------------------------

function [7:0] left_shiftingby_2;
input [7:0] val;
left_shiftingby_2=(val<<2) & 8'hFF;     //(using 8'hFF for avoiding the overflow....it is just like modulo 256)
endfunction

 
 //---------------------------Hashing pipeline-----------------------------------------------

 assign xor_val=xoring_withthe_key(data_in);
 assign shifted_val=left_shiftingby_2(xor_val);
 assign hash_out=shifted_val;

 endmodule