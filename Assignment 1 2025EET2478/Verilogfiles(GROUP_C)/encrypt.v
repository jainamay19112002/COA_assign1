                                            //ENCRYPTION MODULE//

//what is encryption here?
/*It is a way to protect the data or the important information with the help of 
some mathematical tools or models so that no third party users can access it wihtout the help of the key */

module encrypt_spn(
    input wire [7:0] data_input,           //the 8-bit input Plaintext
    output wire [7:0] data_output,         //the final 8- bit Ciphertext
    output wire [7:0] s_box_val,           //intermediate value after substituting from the s_box
    output wire [7:0] perm_val             //intermediate value after permuting 
);

  parameter KEY=8'h5A;                      //Fixed Round key

wire[7:0] xor_val;

//-------------HERE WE ARE SPLITTING THE NIBBLES INTO TWO 4-BIT VALUES-------------------------------

  function [3:0] get_upper;
  input [7:0] in;
  get_upper=in[7:4];
  endfunction;

  function [3:0] get_lower;
  input [7:0] in;
  get_lower=in[3:0];
  endfunction;

  function [7:0] mergingnibbles;
  input [3:0] high,low;
  mergingnibbles={high,low};
  endfunction;


//----------------AES S-BOX LOOKUP TABLE-----------------------------------

function [7:0] s_box_lookup;
input [7:0] in;
begin 
    case(in)
        8'h00: s_box_lookup = 8'h63; 8'h01: s_box_lookup = 8'h7C; 8'h02: s_box_lookup = 8'h77; 8'h03: s_box_lookup = 8'h7B;
        8'h04: s_box_lookup = 8'hF2; 8'h05: s_box_lookup = 8'h6B; 8'h06: s_box_lookup = 8'h6F; 8'h07: s_box_lookup = 8'hC5;
        8'h08: s_box_lookup = 8'h30; 8'h09: s_box_lookup = 8'h01; 8'h0A: s_box_lookup = 8'h67; 8'h0B: s_box_lookup = 8'h2B;
        8'h0C: s_box_lookup = 8'hFE; 8'h0D: s_box_lookup = 8'hD7; 8'h0E: s_box_lookup = 8'hAB; 8'h0F: s_box_lookup = 8'h76;

        8'h10: s_box_lookup = 8'hCA; 8'h11: s_box_lookup = 8'h82; 8'h12: s_box_lookup = 8'hC9; 8'h13: s_box_lookup = 8'h7D;
        8'h14: s_box_lookup = 8'hFA; 8'h15: s_box_lookup = 8'h59; 8'h16: s_box_lookup = 8'h47; 8'h17: s_box_lookup = 8'hF0;
        8'h18: s_box_lookup = 8'hAD; 8'h19: s_box_lookup = 8'hD4; 8'h1A: s_box_lookup = 8'hA2; 8'h1B: s_box_lookup = 8'hAF;
        8'h1C: s_box_lookup = 8'h9C; 8'h1D: s_box_lookup = 8'hA4; 8'h1E: s_box_lookup = 8'h72; 8'h1F: s_box_lookup = 8'hC0;

        8'h20: s_box_lookup = 8'hB7; 8'h21: s_box_lookup = 8'hFD; 8'h22: s_box_lookup = 8'h93; 8'h23: s_box_lookup = 8'h26;
        8'h24: s_box_lookup = 8'h36; 8'h25: s_box_lookup = 8'h3F; 8'h26: s_box_lookup = 8'hF7; 8'h27: s_box_lookup = 8'hCC;
        8'h28: s_box_lookup = 8'h34; 8'h29: s_box_lookup = 8'hA5; 8'h2A: s_box_lookup = 8'hE5; 8'h2B: s_box_lookup = 8'hF1;
        8'h2C: s_box_lookup = 8'h71; 8'h2D: s_box_lookup = 8'hD8; 8'h2E: s_box_lookup = 8'h31; 8'h2F: s_box_lookup = 8'h15;

        8'h30: s_box_lookup = 8'h04; 8'h31: s_box_lookup = 8'hC7; 8'h32: s_box_lookup = 8'h23; 8'h33: s_box_lookup = 8'hC3;
        8'h34: s_box_lookup = 8'h18; 8'h35: s_box_lookup = 8'h96; 8'h36: s_box_lookup = 8'h05; 8'h37: s_box_lookup = 8'h9A;
        8'h38: s_box_lookup = 8'h07; 8'h39: s_box_lookup = 8'h12; 8'h3A: s_box_lookup = 8'h80; 8'h3B: s_box_lookup = 8'hE2;
        8'h3C: s_box_lookup = 8'hEB; 8'h3D: s_box_lookup = 8'h27; 8'h3E: s_box_lookup = 8'hB2; 8'h3F: s_box_lookup = 8'h75;

        8'h40: s_box_lookup = 8'h09; 8'h41: s_box_lookup = 8'h83; 8'h42: s_box_lookup = 8'h2C; 8'h43: s_box_lookup = 8'h1A;
        8'h44: s_box_lookup = 8'h1B; 8'h45: s_box_lookup = 8'h6E; 8'h46: s_box_lookup = 8'h5A; 8'h47: s_box_lookup = 8'hA0;
        8'h48: s_box_lookup = 8'h52; 8'h49: s_box_lookup = 8'h3B; 8'h4A: s_box_lookup = 8'hD6; 8'h4B: s_box_lookup = 8'hB3;
        8'h4C: s_box_lookup = 8'h29; 8'h4D: s_box_lookup = 8'hE3; 8'h4E: s_box_lookup = 8'h2F; 8'h4F: s_box_lookup = 8'h84;

        8'h50: s_box_lookup = 8'h53; 8'h51: s_box_lookup = 8'hD1; 8'h52: s_box_lookup = 8'h00; 8'h53: s_box_lookup = 8'hED;
        8'h54: s_box_lookup = 8'h20; 8'h55: s_box_lookup = 8'hFC; 8'h56: s_box_lookup = 8'hB1; 8'h57: s_box_lookup = 8'h5B;
        8'h58: s_box_lookup = 8'h6A; 8'h59: s_box_lookup = 8'hCB; 8'h5A: s_box_lookup = 8'hBE; 8'h5B: s_box_lookup = 8'h39;
        8'h5C: s_box_lookup = 8'h4A; 8'h5D: s_box_lookup = 8'h4C; 8'h5E: s_box_lookup = 8'h58; 8'h5F: s_box_lookup = 8'hCF;

        8'h60: s_box_lookup = 8'hD0; 8'h61: s_box_lookup = 8'hEF; 8'h62: s_box_lookup = 8'hAA; 8'h63: s_box_lookup = 8'hFB;
        8'h64: s_box_lookup = 8'h43; 8'h65: s_box_lookup = 8'h4D; 8'h66: s_box_lookup = 8'h33; 8'h67: s_box_lookup = 8'h85;
        8'h68: s_box_lookup = 8'h45; 8'h69: s_box_lookup = 8'hF9; 8'h6A: s_box_lookup = 8'h02; 8'h6B: s_box_lookup = 8'h7F;
        8'h6C: s_box_lookup = 8'h50; 8'h6D: s_box_lookup = 8'h3C; 8'h6E: s_box_lookup = 8'h9F; 8'h6F: s_box_lookup = 8'hA8;

        8'h70: s_box_lookup = 8'h51; 8'h71: s_box_lookup = 8'hA3; 8'h72: s_box_lookup = 8'h40; 8'h73: s_box_lookup = 8'h8F;
        8'h74: s_box_lookup = 8'h92; 8'h75: s_box_lookup = 8'h9D; 8'h76: s_box_lookup = 8'h38; 8'h77: s_box_lookup = 8'hF5;
        8'h78: s_box_lookup = 8'hBC; 8'h79: s_box_lookup = 8'hB6; 8'h7A: s_box_lookup = 8'hDA; 8'h7B: s_box_lookup = 8'h21;
        8'h7C: s_box_lookup = 8'h10; 8'h7D: s_box_lookup = 8'hFF; 8'h7E: s_box_lookup = 8'hF3; 8'h7F: s_box_lookup = 8'hD2;

        8'h80: s_box_lookup = 8'hCD; 8'h81: s_box_lookup = 8'h0C; 8'h82: s_box_lookup = 8'h13; 8'h83: s_box_lookup = 8'hEC;
        8'h84: s_box_lookup = 8'h5F; 8'h85: s_box_lookup = 8'h97; 8'h86: s_box_lookup = 8'h44; 8'h87: s_box_lookup = 8'h17;
        8'h88: s_box_lookup = 8'hC4; 8'h89: s_box_lookup = 8'hA7; 8'h8A: s_box_lookup = 8'h7E; 8'h8B: s_box_lookup = 8'h3D;
        8'h8C: s_box_lookup = 8'h64; 8'h8D: s_box_lookup = 8'h5D; 8'h8E: s_box_lookup = 8'h19; 8'h8F: s_box_lookup = 8'h73;

        8'h90: s_box_lookup = 8'h60; 8'h91: s_box_lookup = 8'h81; 8'h92: s_box_lookup = 8'h4F; 8'h93: s_box_lookup = 8'hDC;
        8'h94: s_box_lookup = 8'h22; 8'h95: s_box_lookup = 8'h2A; 8'h96: s_box_lookup = 8'h90; 8'h97: s_box_lookup = 8'h88;
        8'h98: s_box_lookup = 8'h46; 8'h99: s_box_lookup = 8'hEE; 8'h9A: s_box_lookup = 8'hB8; 8'h9B: s_box_lookup = 8'h14;
        8'h9C: s_box_lookup = 8'hDE; 8'h9D: s_box_lookup = 8'h5E; 8'h9E: s_box_lookup = 8'h0B; 8'h9F: s_box_lookup = 8'hDB;

        8'hA0: s_box_lookup = 8'hE0; 8'hA1: s_box_lookup = 8'h32; 8'hA2: s_box_lookup = 8'h3A; 8'hA3: s_box_lookup = 8'h0A;
        8'hA4: s_box_lookup = 8'h49; 8'hA5: s_box_lookup = 8'h06; 8'hA6: s_box_lookup = 8'h24; 8'hA7: s_box_lookup = 8'h5C;
        8'hA8: s_box_lookup = 8'hC2; 8'hA9: s_box_lookup = 8'hD3; 8'hAA: s_box_lookup = 8'hAC; 8'hAB: s_box_lookup = 8'h62;
        8'hAC: s_box_lookup = 8'h91; 8'hAD: s_box_lookup = 8'h95; 8'hAE: s_box_lookup = 8'hE4; 8'hAF: s_box_lookup = 8'h79;

        8'hB0: s_box_lookup = 8'hE7; 8'hB1: s_box_lookup = 8'hC8; 8'hB2: s_box_lookup = 8'h37; 8'hB3: s_box_lookup = 8'h6D;
        8'hB4: s_box_lookup = 8'h8D; 8'hB5: s_box_lookup = 8'hD5; 8'hB6: s_box_lookup = 8'h4E; 8'hB7: s_box_lookup = 8'hA9;
        8'hB8: s_box_lookup = 8'h6C; 8'hB9: s_box_lookup = 8'h56; 8'hBA: s_box_lookup = 8'hF4; 8'hBB: s_box_lookup = 8'hEA;
        8'hBC: s_box_lookup = 8'h65; 8'hBD: s_box_lookup = 8'h7A; 8'hBE: s_box_lookup = 8'hAE; 8'hBF: s_box_lookup = 8'h08;

        8'hC0: s_box_lookup = 8'hBA; 8'hC1: s_box_lookup = 8'h78; 8'hC2: s_box_lookup = 8'h25; 8'hC3: s_box_lookup = 8'h2E;
        8'hC4: s_box_lookup = 8'h1C; 8'hC5: s_box_lookup = 8'hA6; 8'hC6: s_box_lookup = 8'hB4; 8'hC7: s_box_lookup = 8'hC6;
        8'hC8: s_box_lookup = 8'hE8; 8'hC9: s_box_lookup = 8'hDD; 8'hCA: s_box_lookup = 8'h74; 8'hCB: s_box_lookup = 8'h1F;
        8'hCC: s_box_lookup = 8'h4B; 8'hCD: s_box_lookup = 8'hBD; 8'hCE: s_box_lookup = 8'h8B; 8'hCF: s_box_lookup = 8'h8A;

        8'hD0: s_box_lookup = 8'h70; 8'hD1: s_box_lookup = 8'h3E; 8'hD2: s_box_lookup = 8'hB5; 8'hD3: s_box_lookup = 8'h66;
        8'hD4: s_box_lookup = 8'h48; 8'hD5: s_box_lookup = 8'h03; 8'hD6: s_box_lookup = 8'hF6; 8'hD7: s_box_lookup = 8'h0E;
        8'hD8: s_box_lookup = 8'h61; 8'hD9: s_box_lookup = 8'h35; 8'hDA: s_box_lookup = 8'h57; 8'hDB: s_box_lookup = 8'hB9;
        8'hDC: s_box_lookup = 8'h86; 8'hDD: s_box_lookup = 8'hC1; 8'hDE: s_box_lookup = 8'h1D; 8'hDF: s_box_lookup = 8'h9E;

        8'hE0: s_box_lookup = 8'hE1; 8'hE1: s_box_lookup = 8'hF8; 8'hE2: s_box_lookup = 8'h98; 8'hE3: s_box_lookup = 8'h11;
        8'hE4: s_box_lookup = 8'h69; 8'hE5: s_box_lookup = 8'hD9; 8'hE6: s_box_lookup = 8'h8E; 8'hE7: s_box_lookup = 8'h94;
        8'hE8: s_box_lookup = 8'h9B; 8'hE9: s_box_lookup = 8'h1E; 8'hEA: s_box_lookup = 8'h87; 8'hEB: s_box_lookup = 8'hE9;
        8'hEC: s_box_lookup = 8'hCE; 8'hED: s_box_lookup = 8'h55; 8'hEE: s_box_lookup = 8'h28; 8'hEF: s_box_lookup = 8'hDF;

        8'hF0: s_box_lookup = 8'h8C; 8'hF1: s_box_lookup = 8'hA1; 8'hF2: s_box_lookup = 8'h89; 8'hF3: s_box_lookup = 8'h0D;
        8'hF4: s_box_lookup = 8'hBF; 8'hF5: s_box_lookup = 8'hE6; 8'hF6: s_box_lookup = 8'h42; 8'hF7: s_box_lookup = 8'h68;
        8'hF8: s_box_lookup = 8'h41; 8'hF9: s_box_lookup = 8'h99; 8'hFA: s_box_lookup = 8'h2D; 8'hFB: s_box_lookup = 8'h0F;
        8'hFC: s_box_lookup = 8'hB0; 8'hFD: s_box_lookup = 8'h54; 8'hFE: s_box_lookup = 8'hBB; 8'hFF: s_box_lookup = 8'h16;


    default: s_box_lookup=8'h00;
    endcase
end
endfunction


//---------------------------PERMUTATING OF THE NIBBLES------------------------------

function[7:0] swapping_nibbles;
input [7:0] in;
reg [3:0] high,low;
begin 
    high=get_upper(in);
    low=get_lower(in);
    swapping_nibbles=mergingnibbles(low,high);
end
endfunction


//-----------------------------ENCRYPTING THE PIPELINE-------------------------------------


assign s_box_val=s_box_lookup(data_input);
assign perm_val=swapping_nibbles(s_box_val);
assign xor_val=perm_val ^ KEY;
assign data_output=xor_val;

endmodule



