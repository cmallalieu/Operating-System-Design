#include <string>

#include "../common/crypto.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_commands.h"
#include "server_storage.h"

using namespace std;

/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_all(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  
   // get indexes of newline delimeters in req
  vector<size_t> newline_indexes = find_k_newlines(req);
  // username is index 0, password index 1
  vec username_password[2];

  // write error if incorrent number of words in req
  if (newline_indexes.size() != 1)
  {
    // encrypt error before writing to socket
    vec err_response = vec_from_string(RES_ERR_MSG_FMT);
    vec err_response_enc = aes_crypt_msg(ctx, err_response);
    // write error response to socket and then close it 
    send_reliably(sd, err_response_enc);
    close(sd);
    return false;
  }


  vec response;
  size_t j = 0;

  // parse the req for the username and password
  for (size_t i = 0; i < newline_indexes.size(); i++)
  {
    vec curr_word = {};
    while (j < newline_indexes[i])
    {
      curr_word.push_back(req[j]);
      j++;
    }
    username_password[i] = curr_word;
  }

  pair<bool, vec> usernames = storage.get_all_users(string(username_password[0].begin(), username_password[0].end()), 
                                              string(username_password[1].begin(), 
                                              username_password[1].end()));

  // on successful get of username list
  if (!get<0>(usernames))
  {
    // remove trailing newline character
    get<1>(usernames).pop_back();

    size_t len_usernames = get<1>(usernames).size(); 
    vec success_response = vec_from_string(RES_OK);

    // create response format
    vec_append(success_response, len_usernames);
    vec_append(success_response, get<1>(usernames));

    // encrypt response, write to socket, close socket
    vec success_response_enc = aes_crypt_msg(ctx, success_response);
    send_reliably(sd, success_response_enc);
    close(sd);

    return false;
  }
  else
  {
    // encrypt error before writing to socket
    vec err_response = get<1>(usernames);
    vec err_response_enc = aes_crypt_msg(ctx, err_response);
    // write error response to socket and then close it 
    send_reliably(sd, err_response_enc);
    close(sd);
    return true;
  }
}

/// Respond to a SET command by putting the provided data into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_set(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  /*
    vec Storage::set_user_data(const string &user_name, const string &pass,
    const vec &content)
  */
  // get indexes of newline delimeters in req
  vector<size_t> newline_indexes = find_k_newlines(req);
  // username is index 0, password index 1
  vec username_password_contentLen_content[4];

  if (newline_indexes.size() != 3)
  {
    // encrypt error before writing to socket
    vec err_response = vec_from_string(RES_ERR_MSG_FMT);
    vec err_response_enc = aes_crypt_msg(ctx, err_response);
    // write error response to socket and then close it 
    send_reliably(sd, err_response_enc);
    close(sd);
    return false;
  }

  vec response;
  size_t j = 0;

  // parse the req for the username and password
  for (size_t i = 0; i < newline_indexes.size(); i++)
  {
    vec curr_word = {};
    while (j < newline_indexes[i])
    {
      curr_word.push_back(req[j]);
      j++;
    }
    username_password_contentLen_content[i] = curr_word;
  }

  // set user data into storage object
  response = storage.set_user_data(string(username_password_contentLen_content[0].begin(),
                       username_password_contentLen_content[0].end()), 
                       string(username_password_contentLen_content[1].begin(), 
                       username_password_contentLen_content[1].end()), 
                       username_password_contentLen_content[3]);


  // create full response
  vec_append(response, username_password_contentLen_content[3]);
  vec_append(response, username_password_contentLen_content[4]);

  // error message are handled by set user so send response 
  vec response_enc = aes_crypt_msg(ctx, response);
  // write error response to socket and then close it 
  send_reliably(sd, response_enc);
  close(sd);

  return false;
}

/// Respond to a GET command by getting the data for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_get(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {

  // get indexes of newline delimeters in req
  vector<size_t> newline_indexes = find_k_newlines(req);
  // username is index 0, password index 1
  vec username_password_searchUser[3];

  // write error if incorrent number of words in req
  if (newline_indexes.size() != 2)
  {
    // encrypt error before writing to socket
    vec err_response = vec_from_string(RES_ERR_MSG_FMT);
    vec err_response_enc = aes_crypt_msg(ctx, err_response);
    // write error response to socket and then close it 
    send_reliably(sd, err_response_enc);
    close(sd);
    return true;
  }


  vec response;
  size_t j = 0;

  // parse the req for the username and password and search username
  for (size_t i = 0; i < newline_indexes.size(); i++)
  {
    vec curr_word = {};
    while (j < newline_indexes[i])
    {
      curr_word.push_back(req[j]);
      j++;
    }
    username_password_searchUser[i] = curr_word;
  }

  // get response message from get_user_Data
  pair<bool, vec> get_return = storage.get_user_data(string(username_password_searchUser[0].begin(),
                                username_password_searchUser[0].end()), string(username_password_searchUser[1].begin(),
                                  username_password_searchUser[1].end()), string(username_password_searchUser[2].begin(), 
                                    username_password_searchUser[2].end()));
  
  // if the get was successful
  if (get<0>(get_return))
  {
    vec success_response = vec_from_string(RES_OK);
    size_t content_len = get<1>(get_return).size();

    // create full success response
    vec_append(success_response, content_len);
    vec_append(success_response, get<1>(get_return));

    //encrypt, send and close socket
    vec success_response_enc = aes_crypt_msg(ctx, success_response);
    send_reliably(sd, success_response_enc);
    close(sd);
    return false;
  }
  else
  {
    // error message handled by call to get_user_data, encrypt and send
    vec err_response_enc = aes_crypt_msg(ctx, get<1>(get_return));
    // write error response to socket and then close it 
    send_reliably(sd, err_response_enc);
    close(sd);
    return true;
  }
}

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop

// 1. parse req in from @u."\n".@p for username and password
// 2. call add user on storage object
// 3. on succesful add, encrypt "OK" and close socket
// 4. on unsuccesful add,
bool server_cmd_reg(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {

  // get indexes of newline delimeters in req
  vector<size_t> newline_indexes = find_k_newlines(req);
  // username is index 0, password index 1
  vec username_password[2];

  //return error if incorrect number of args in req
  if (newline_indexes.size() != 1)
  {
    // encrypt error before writing to socket
    vec err_response = vec_from_string(RES_ERR_MSG_FMT);
    vec err_response_enc = aes_crypt_msg(ctx, err_response);
    // write error response to socket and then close it 
    send_reliably(sd, err_response_enc);
    close(sd);
    return false;
  }

  vec response;
  size_t j = 0;

  // parse the req for the username and password
  for (size_t i = 0; i < newline_indexes.size(); i++)
  {
    vec curr_word = {};
    while (j < newline_indexes[i])
    {
      curr_word.push_back(req[j]);
      j++;
    }
    username_password[i] = curr_word;
  }

  // if add user was not successfull, send error to client
  if (!storage.add_user(string(reinterpret_cast<const char*>(username_password[0].data())),
                     string(reinterpret_cast<const char*>(username_password[1].data()))))
  {
    // encrypt error before writing to socket
    vec err_response = vec_from_string(RES_ERR_USER_EXISTS);
    vec err_response_enc = aes_crypt_msg(ctx, err_response);
    // write error response to socket and then close it 
    send_reliably(sd, err_response_enc);
    close(sd);
    return true;
  }
  else
  {
    // on successfull user add, encrypt message, write to socket, and close socket
    vec success_response = vec_from_string(RES_OK);
    vec success_response_enc = aes_crypt_msg(ctx, success_response);
    send_reliably(sd, success_response_enc);
    close(sd);
  }
  return false;
}

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents

void server_cmd_key(int sd, const vec &pubfile) {
  send_reliably(sd, pubfile);
  close(sd);
}

/// Respond to a BYE command by returning false, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns true, to indicate that the server should stop, or false on an error

bool server_cmd_bye(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {

  // get indexes of words in msg
  vector<size_t> newline_indexes = find_k_newlines(req);

  // if there are not two word in the request, write error and close socket
  if (newline_indexes.size() != 1)
  {
    // encrypt error before writing to socket
    vec err_response = vec_from_string(RES_ERR_MSG_FMT);
    vec err_response_enc = aes_crypt_msg(ctx, err_response);
    // write error response to socket and then close it 
    send_reliably(sd, err_response_enc);
    close(sd);
    return false;
  }

  // username is index 0 password index 1
  vec username_password[2];

  vec response;
  size_t j = 0;

  // parse the req for the username and password
  for (size_t i = 0; i < newline_indexes.size(); i++)
  {
    vec curr_word = {};
    while (j < newline_indexes[i])
    {
      curr_word.push_back(req[j]);
      j++;
    }
    username_password[i] = curr_word;
  }

  // if valid username and password are passed
  if (storage.auth(string(username_password[0].begin(), username_password[0].end()), 
                    string(username_password[1].begin(), username_password[1].end())))
  {
    storage.persist();
    // on success , encrypt message, write to socket, and close socket
    vec success_response = vec_from_string(RES_OK);
    vec success_response_enc = aes_crypt_msg(ctx, success_response);
    send_reliably(sd, success_response_enc);
    close(sd);
    return true;
  }
  // if authentication fails
  else
  {
    // encrypt error before writing to socket
    vec err_response = vec_from_string(RES_ERR_LOGIN);
    vec err_response_enc = aes_crypt_msg(ctx, err_response);
    // write error response to socket and then close it 
    send_reliably(sd, err_response_enc);
    close(sd);
    return false;
  }
}

/// Respond to a SAV command by persisting the file, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_sav(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  // get indexes of words in msg
  vector<size_t> newline_indexes = find_k_newlines(req);

  // if there are not two word in the request, write error and close socket
  if (newline_indexes.size() != 1)
  {
    // encrypt error before writing to socket
    vec err_response = vec_from_string(RES_ERR_MSG_FMT);
    vec err_response_enc = aes_crypt_msg(ctx, err_response);
    // write error response to socket and then close it 
    send_reliably(sd, err_response_enc);
    close(sd);
    return false;
  }

  // username is index 0 password index 1
  vec username_password[2];

  vec response;
  size_t j = 0;

  // parse the req for the username and password
  for (size_t i = 0; i < newline_indexes.size(); i++)
  {
    vec curr_word = {};
    while (j < newline_indexes[i])
    {
      curr_word.push_back(req[j]);
      j++;
    }
    username_password[i] = curr_word;
  }

  // if valid username and password are passed
  if (storage.auth(string(username_password[0].begin(), username_password[0].end()), 
                    string(username_password[1].begin(), username_password[1].end())))
  {
    storage.persist();
    // on success , encrypt message, write to socket, and close socket
    vec success_response = vec_from_string(RES_OK);
    vec success_response_enc = aes_crypt_msg(ctx, success_response);
    send_reliably(sd, success_response_enc);
    close(sd);
    return false;
  }
  else
  {
    // encrypt error before writing to socket   
    vec err_response = vec_from_string(RES_ERR_LOGIN);
    vec err_response_enc = aes_crypt_msg(ctx, err_response);
    // write error response to socket and then close it 
    send_reliably(sd, err_response_enc);
    close(sd);
    return false;
  }

  return false;
}


std::vector<size_t> find_k_newlines(const vec &msg)
{
  vector<size_t> newline_indexes;
  for (size_t i = 0; i < msg.size(); i++)
  {
    if (msg[i] == '\n')
    {
      newline_indexes.push_back(i);
    }
  }
  return newline_indexes;
}