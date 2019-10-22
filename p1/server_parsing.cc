#include <cstring>
#include <iostream>
#include <openssl/rsa.h>
#include <string>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_commands.h"
#include "server_parsing.h"
#include "server_storage.h"

using namespace std;

// ./obj64/server.exe -p 9999 -k rsa -f company.dir -t 1 -b 16 -i 60 -u 1048576 -d 1048576 -r 128 -o 4 -a

/// When a new client connection is accepted, this code will run to figure out
/// what the client is requesting, and to dispatch to the right function for
/// satisfying the request.
///
/// @param sd      The socket on which communication with the client takes place
/// @param pri     The private key used by the server
/// @param pub     The public key file contents, to send to the client
/// @param storage The Storage object with which clients interact
///
/// @returns true if the server should halt immediately, false otherwise
bool serve_client(int sd, RSA *pri, const vec &pub, Storage &storage) {

  // read RBLOCK or KBLOCK
  vec r_block;
  int bytes_read = reliable_get_to_eof_or_n(sd, r_block.begin(), LEN_RKBLOCK);

  // return error if no bytes were read from socket
  if (bytes_read != LEN_RKBLOCK)
  {
    return true;
  }

  //decrypt RBLOCK OR KBLOCK
  char decrypted_rblock[LEN_RBLOCK_CONTENT];
  int* len_r_content = (int *)&LEN_RBLOCK_CONTENT;
  rsa_decrypt(pri, reinterpret_cast<char*>(r_block.data()), 
                LEN_RKBLOCK, decrypted_rblock, *len_r_content);
  
  // if the client sends a key request, send the public key
  vec rblock_dec_vec = vec_from_string(string(decrypted_rblock));
  if (is_kblock(rblock_dec_vec))
  {
    server_cmd_key(sd, pub);
    return false;
  }


// change next reliable get
  // parse RBLOCK
  string cmd = string(decrypted_rblock).substr(0, 2);
  string aes_key = string(decrypted_rblock).substr(3, AES_KEYSIZE + 2);
  string content_length = string(decrypted_rblock).substr(AES_KEYSIZE + 3, LEN_RBLOCK_CONTENT);

  // read encrypted ABLOCK
  vec enc_ablock;
  bytes_read = reliable_get_to_eof_or_n(sd, enc_ablock.begin(), stoi(content_length));
  
  // return error if no bytes were read from socket
  if (bytes_read != stoi(content_length))
  {
    return true;
  }

  // create AES context
  EVP_CIPHER_CTX* aes_ctx = create_aes_context(vec_from_string(aes_key), false);

  // decrypt ABLOCK
  vec decrypted_ablock = aes_crypt_msg(aes_ctx, enc_ablock);
    
  // get content from ABLOCK
  string msg = string(reinterpret_cast<const char*>(decrypted_ablock.data()));

  // Iterate through possible commands, pick the right one, run it
  vector<string> s = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
  decltype(server_cmd_reg) *cmds[] = {server_cmd_reg, server_cmd_bye,
                                      server_cmd_sav, server_cmd_set,
                                      server_cmd_get, server_cmd_all};
  for (size_t i = 0; i < s.size(); ++i) {
    if (cmd == s[i]) {
      return cmds[i](sd, storage, aes_ctx, vec_from_string(msg));
    }
  }

  return false;
}

/// Helper method to check if the provided block of data is a kblock
///
/// @param block The block of data
///
/// @returns true if it is a kblock, false otherwise
bool is_kblock(vec &block) {
  string block_str = string(reinterpret_cast<const char*>(block.data()));
  if (!block_str.substr(0, 2).compare(REQ_KEY))
  {
    return true;
  }
  return false;
}
