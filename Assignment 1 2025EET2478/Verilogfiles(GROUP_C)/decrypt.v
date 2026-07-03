                                           //DECRYPTION MODULE//

//what is decryption here?
/*It is a way to transform encrypted information into the original format. It converts the ciphertext into
the plaintext using the cryptographic key. */

module decrypt_spn(
    input wire [7:0] data_input,            //Plaintext
    output wire [7:0] data_output,         //Ciphertext
    output wire [7:0] key_xor,             //Debugging after Xoring
    output wire [7:0] perm_val             //Debugging after the permutation
);

  parameter KEY=8'h5A;                      //Fixed Round key


  //-------------SPLITTING THE NIBBLES-------------------------------

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


//----------------AES INVERSE S-BOX LOOKUP TABLE-----------------------------------

function [7:0] inv_s_box_lookup;
input [7:0] in;
begin 
    case(in)
        8'h00: inv_s_box_lookup=8'h52; 8'h01: inv_s_box_lookup=8'h09; 8'h02: inv_s_box_lookup=8'h6A; 8'h03: inv_s_box_lookup=8'hD5;
        8'h04: inv_s_box_lookup=8'h30; 8'h05: inv_s_box_lookup=8'h36; 8'h06: inv_s_box_lookup=8'hA5; 8'h07: inv_s_box_lookup=8'h38;
        8'h08: inv_s_box_lookup=8'hBF; 8'h09: inv_s_box_lookup=8'h40; 8'h0A: inv_s_box_lookup=8'hA3; 8'h0B: inv_s_box_lookup=8'h9E;
        8'h0C: inv_s_box_lookup=8'h81; 8'h0D: inv_s_box_lookup=8'hF3; 8'h0E: inv_s_box_lookup=8'hD7; 8'h0F: inv_s_box_lookup=8'hFB;

        8'h10: inv_s_box_lookup=8'h7C; 8'h11: inv_s_box_lookup=8'hE3; 8'h12: inv_s_box_lookup=8'h39; 8'h13: inv_s_box_lookup=8'h82;
        8'h14: inv_s_box_lookup=8'h9B; 8'h15: inv_s_box_lookup=8'h2F; 8'h16: inv_s_box_lookup=8'hFF; 8'h17: inv_s_box_lookup=8'h87;
        8'h18: inv_s_box_lookup=8'h34; 8'h19: inv_s_box_lookup=8'h8E; 8'h1A: inv_s_box_lookup=8'h43; 8'h1B: inv_s_box_lookup=8'h44;
        8'h1C: inv_s_box_lookup=8'hC4; 8'h1D: inv_s_box_lookup=8'hDE; 8'h1E: inv_s_box_lookup=8'hE9; 8'h1F: inv_s_box_lookup=8'hCB;

        8'h20: inv_s_box_lookup=8'h54; 8'h21: inv_s_box_lookup=8'h7B; 8'h22: inv_s_box_lookup=8'h94; 8'h23: inv_s_box_lookup=8'h32;
        8'h24: inv_s_box_lookup=8'hA6; 8'h25: inv_s_box_lookup=8'hC2; 8'h26: inv_s_box_lookup=8'h23; 8'h27: inv_s_box_lookup=8'h3D;
        8'h28: inv_s_box_lookup=8'hEE; 8'h29: inv_s_box_lookup=8'h4C; 8'h2A: inv_s_box_lookup=8'h95; 8'h2B: inv_s_box_lookup=8'h0B;
        8'h2C: inv_s_box_lookup=8'h42; 8'h2D: inv_s_box_lookup=8'hFA; 8'h2E: inv_s_box_lookup=8'hC3; 8'h2F: inv_s_box_lookup=8'h4E;

        8'h30: inv_s_box_lookup=8'h08; 8'h31: inv_s_box_lookup=8'h2E; 8'h32: inv_s_box_lookup=8'hA1; 8'h33: inv_s_box_lookup=8'h66;
        8'h34: inv_s_box_lookup=8'h28; 8'h35: inv_s_box_lookup=8'hD9; 8'h36: inv_s_box_lookup=8'h24; 8'h37: inv_s_box_lookup=8'hB2;
        8'h38: inv_s_box_lookup=8'h76; 8'h39: inv_s_box_lookup=8'h5B; 8'h3A: inv_s_box_lookup=8'hA2; 8'h3B: inv_s_box_lookup=8'h49;
        8'h3C: inv_s_box_lookup=8'h6D; 8'h3D: inv_s_box_lookup=8'h8B; 8'h3E: inv_s_box_lookup=8'hD1; 8'h3F: inv_s_box_lookup=8'h25;

        8'h40: inv_s_box_lookup=8'h72; 8'h41: inv_s_box_lookup=8'hF8; 8'h42: inv_s_box_lookup=8'hF6; 8'h43: inv_s_box_lookup=8'h64;
        8'h44: inv_s_box_lookup=8'h86; 8'h45: inv_s_box_lookup=8'h68; 8'h46: inv_s_box_lookup=8'h98; 8'h47: inv_s_box_lookup=8'h16;
        8'h48: inv_s_box_lookup=8'hD4; 8'h49: inv_s_box_lookup=8'hA4; 8'h4A: inv_s_box_lookup=8'h5C; 8'h4B: inv_s_box_lookup=8'hCC;
        8'h4C: inv_s_box_lookup=8'h5D; 8'h4D: inv_s_box_lookup=8'h65; 8'h4E: inv_s_box_lookup=8'hB6; 8'h4F: inv_s_box_lookup=8'h92;

        8'h50: inv_s_box_lookup=8'h6C; 8'h51: inv_s_box_lookup=8'h70; 8'h52: inv_s_box_lookup=8'h48; 8'h53: inv_s_box_lookup=8'h50;
        8'h54: inv_s_box_lookup=8'hFD; 8'h55: inv_s_box_lookup=8'hED; 8'h56: inv_s_box_lookup=8'hB9; 8'h57: inv_s_box_lookup=8'hDA;
        8'h58: inv_s_box_lookup=8'h5E; 8'h59: inv_s_box_lookup=8'h15; 8'h5A: inv_s_box_lookup=8'h46; 8'h5B: inv_s_box_lookup=8'h57;
        8'h5C: inv_s_box_lookup=8'hA7; 8'h5D: inv_s_box_lookup=8'h8D; 8'h5E: inv_s_box_lookup=8'h9D; 8'h5F: inv_s_box_lookup=8'h84;

        8'h60: inv_s_box_lookup=8'h90; 8'h61: inv_s_box_lookup=8'hD8; 8'h62: inv_s_box_lookup=8'hAB; 8'h63: inv_s_box_lookup=8'h00;
        8'h64: inv_s_box_lookup=8'h8C; 8'h65: inv_s_box_lookup=8'hBC; 8'h66: inv_s_box_lookup=8'hD3; 8'h67: inv_s_box_lookup=8'h0A;
        8'h68: inv_s_box_lookup=8'hF7; 8'h69: inv_s_box_lookup=8'hE4; 8'h6A: inv_s_box_lookup=8'h58; 8'h6B: inv_s_box_lookup=8'h05;
        8'h6C: inv_s_box_lookup=8'hB8; 8'h6D: inv_s_box_lookup=8'hB3; 8'h6E: inv_s_box_lookup=8'h45; 8'h6F: inv_s_box_lookup=8'h06;

        8'h70: inv_s_box_lookup=8'hD0; 8'h71: inv_s_box_lookup=8'h2C; 8'h72: inv_s_box_lookup=8'h1E; 8'h73: inv_s_box_lookup=8'h8F;
        8'h74: inv_s_box_lookup=8'hCA; 8'h75: inv_s_box_lookup=8'h3F; 8'h76: inv_s_box_lookup=8'h0F; 8'h77: inv_s_box_lookup=8'h02;
        8'h78: inv_s_box_lookup=8'hC1; 8'h79: inv_s_box_lookup=8'hAF; 8'h7A: inv_s_box_lookup=8'hBD; 8'h7B: inv_s_box_lookup=8'h03;
        8'h7C: inv_s_box_lookup=8'h01; 8'h7D: inv_s_box_lookup=8'h13; 8'h7E: inv_s_box_lookup=8'h8A; 8'h7F: inv_s_box_lookup=8'h6B;

        8'h80: inv_s_box_lookup=8'h3A; 8'h81: inv_s_box_lookup=8'h91; 8'h82: inv_s_box_lookup=8'h11; 8'h83: inv_s_box_lookup=8'h41;
        8'h84: inv_s_box_lookup=8'h4F; 8'h85: inv_s_box_lookup=8'h67; 8'h86: inv_s_box_lookup=8'hDC; 8'h87: inv_s_box_lookup=8'hEA;
        8'h88: inv_s_box_lookup=8'h97; 8'h89: inv_s_box_lookup=8'hF2; 8'h8A: inv_s_box_lookup=8'hCF; 8'h8B: inv_s_box_lookup=8'hCE;
        8'h8C: inv_s_box_lookup=8'hF0; 8'h8D: inv_s_box_lookup=8'hB4; 8'h8E: inv_s_box_lookup=8'hE6; 8'h8F: inv_s_box_lookup=8'h73;

        8'h90: inv_s_box_lookup=8'h96; 8'h91: inv_s_box_lookup=8'hAC; 8'h92: inv_s_box_lookup=8'h74; 8'h93: inv_s_box_lookup=8'h22;
        8'h94: inv_s_box_lookup=8'hE7; 8'h95: inv_s_box_lookup=8'hAD; 8'h96: inv_s_box_lookup=8'h35; 8'h97: inv_s_box_lookup=8'h85;
        8'h98: inv_s_box_lookup=8'hE2; 8'h99: inv_s_box_lookup=8'hF9; 8'h9A: inv_s_box_lookup=8'h37; 8'h9B: inv_s_box_lookup=8'hE8;
        8'h9C: inv_s_box_lookup=8'h1C; 8'h9D: inv_s_box_lookup=8'h75; 8'h9E: inv_s_box_lookup=8'hDF; 8'h9F: inv_s_box_lookup=8'h6E;

        8'hA0: inv_s_box_lookup=8'h47; 8'hA1: inv_s_box_lookup=8'hF1; 8'hA2: inv_s_box_lookup=8'h1A; 8'hA3: inv_s_box_lookup=8'h71;
        8'hA4: inv_s_box_lookup=8'h1D; 8'hA5: inv_s_box_lookup=8'h29; 8'hA6: inv_s_box_lookup=8'hC5; 8'hA7: inv_s_box_lookup=8'h89;
        8'hA8: inv_s_box_lookup=8'h6F; 8'hA9: inv_s_box_lookup=8'hB7; 8'hAA: inv_s_box_lookup=8'h62; 8'hAB: inv_s_box_lookup=8'h0E;
        8'hAC: inv_s_box_lookup=8'hAA; 8'hAD: inv_s_box_lookup=8'h18; 8'hAE: inv_s_box_lookup=8'hBE; 8'hAF: inv_s_box_lookup=8'h1B;

        8'hB0: inv_s_box_lookup=8'hFC; 8'hB1: inv_s_box_lookup=8'h56; 8'hB2: inv_s_box_lookup=8'h3E; 8'hB3: inv_s_box_lookup=8'h4B;
        8'hB4: inv_s_box_lookup=8'hC6; 8'hB5: inv_s_box_lookup=8'hD2; 8'hB6: inv_s_box_lookup=8'h79; 8'hB7: inv_s_box_lookup=8'h20;
        8'hB8: inv_s_box_lookup=8'h9A; 8'hB9: inv_s_box_lookup=8'hDB; 8'hBA: inv_s_box_lookup=8'hC0; 8'hBB: inv_s_box_lookup=8'hFE;
        8'hBC: inv_s_box_lookup=8'h78; 8'hBD: inv_s_box_lookup=8'hCD; 8'hBE: inv_s_box_lookup=8'h5A; 8'hBF: inv_s_box_lookup=8'hF4;

        8'hC0: inv_s_box_lookup=8'h1F; 8'hC1: inv_s_box_lookup=8'hDD; 8'hC2: inv_s_box_lookup=8'hA8; 8'hC3: inv_s_box_lookup=8'h33;
        8'hC4: inv_s_box_lookup=8'h88; 8'hC5: inv_s_box_lookup=8'h07; 8'hC6: inv_s_box_lookup=8'hC7; 8'hC7: inv_s_box_lookup=8'h31;
        8'hC8: inv_s_box_lookup=8'hB1; 8'hC9: inv_s_box_lookup=8'h12; 8'hCA: inv_s_box_lookup=8'h10; 8'hCB: inv_s_box_lookup=8'h59;
        8'hCC: inv_s_box_lookup=8'h27; 8'hCD: inv_s_box_lookup=8'h80; 8'hCE: inv_s_box_lookup=8'hEC; 8'hCF: inv_s_box_lookup=8'h5F;

        8'hD0: inv_s_box_lookup=8'h60; 8'hD1: inv_s_box_lookup=8'h51; 8'hD2: inv_s_box_lookup=8'h7F; 8'hD3: inv_s_box_lookup=8'hA9;
        8'hD4: inv_s_box_lookup=8'h19; 8'hD5: inv_s_box_lookup=8'hB5; 8'hD6: inv_s_box_lookup=8'h4A; 8'hD7: inv_s_box_lookup=8'h0D;
        8'hD8: inv_s_box_lookup=8'h2D; 8'hD9: inv_s_box_lookup=8'hE5; 8'hDA: inv_s_box_lookup=8'h7A; 8'hDB: inv_s_box_lookup=8'h9F;
        8'hDC: inv_s_box_lookup=8'h93; 8'hDD: inv_s_box_lookup=8'hC9; 8'hDE: inv_s_box_lookup=8'h9C; 8'hDF: inv_s_box_lookup=8'hEF;

        8'hE0: inv_s_box_lookup=8'hA0; 8'hE1: inv_s_box_lookup=8'hE0; 8'hE2: inv_s_box_lookup=8'h3B; 8'hE3: inv_s_box_lookup=8'h4D;
        8'hE4: inv_s_box_lookup=8'hAE; 8'hE5: inv_s_box_lookup=8'h2A; 8'hE6: inv_s_box_lookup=8'hF5; 8'hE7: inv_s_box_lookup=8'hB0;
        8'hE8: inv_s_box_lookup=8'hC8; 8'hE9: inv_s_box_lookup=8'hEB; 8'hEA: inv_s_box_lookup=8'hBB; 8'hEB: inv_s_box_lookup=8'h3C;
        8'hEC: inv_s_box_lookup=8'h83; 8'hED: inv_s_box_lookup=8'h53; 8'hEE: inv_s_box_lookup=8'h99; 8'hEF: inv_s_box_lookup=8'h61;

        8'hF0: inv_s_box_lookup=8'h17; 8'hF1: inv_s_box_lookup=8'h2B; 8'hF2: inv_s_box_lookup=8'h04; 8'hF3: inv_s_box_lookup=8'h7E;
        8'hF4: inv_s_box_lookup=8'hBA; 8'hF5: inv_s_box_lookup=8'h77; 8'hF6: inv_s_box_lookup=8'hD6; 8'hF7: inv_s_box_lookup=8'h26;
        8'hF8: inv_s_box_lookup=8'hE1; 8'hF9: inv_s_box_lookup=8'h69; 8'hFA: inv_s_box_lookup=8'h14; 8'hFB: inv_s_box_lookup=8'h63;
        8'hFC: inv_s_box_lookup=8'h55; 8'hFD: inv_s_box_lookup=8'h21; 8'hFE: inv_s_box_lookup=8'h0C; 8'hFF: inv_s_box_lookup=8'h7D;
    


    default: inv_s_box_lookup=8'h00;
    endcase
end
endfunction


//---------------------------INVERSE PERMUTATING OF THE NIBBLES------------------------------

function[7:0] inv_permutethe_bits;
input [7:0] in;
reg [3:0] high,low;
begin 
    high=get_upper(in);
    low=get_lower(in);
    inv_permutethe_bits=mergingnibbles(low,high);
end
endfunction

//-----------------------------DECRYPTING THE PIPELINE-------------------------------------

assign key_xor=data_input ^ KEY;
assign perm_val=inv_permutethe_bits(key_xor);
assign data_output=inv_s_box_lookup(perm_val);

endmodule
