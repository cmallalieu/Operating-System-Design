#include <iostream>
#include <openssl/md5.h>
#include <unordered_map>
#include <utility>
#include <cstdio>
#include <fstream>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_storage.h"

using namespace std;

/// Storage::Internal is the private struct that holds all of the fields of the
/// Storage object.  Organizing the fields as an Internal is part of the PIMPL
/// pattern.
struct Storage::Internal {
  /// AuthTableEntry represents one user stored in the authentication table
  struct AuthTableEntry {
    /// The name of the user; max 64 characters
    string username;

    /// The hashed password.  Note that the password is a max of 128 chars
    string pass_hash;

    /// The user's content
    vec content;
  };

  /// A unique 8-byte code to use as a prefix each time an AuthTable Entry is
  /// written to disk.
  ///
  /// NB: this isn't needed in assignment 1, but will be useful for backwards
  ///     compatibility later on.
  inline static const string AUTHENTRY = "AUTHAUTH";

  /// The map of authentication information, indexed by username
  unordered_map<string, AuthTableEntry> auth_table;

  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  string filename = "";

  /// Construct the Storage::Internal object by setting the filename
  ///
  /// @param fname The name of the file that should be used to load/store the
  ///              data
  Internal(const string &fname) : filename(fname) {}
};

/// Construct an empty object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname The name of the file that should be used to load/store the
///              data
Storage::Storage(const string &fname) : fields(new Internal(fname)) {}

/// Destructor for the storage object.
///
/// NB: The compiler doesn't know that it can create the default destructor in
///     the .h file, because PIMPL prevents it from knowing the size of
///     Storage::Internal.  Now that we have reified Storage::Internal, the
///     compiler can make a destructor for us.
Storage::~Storage() = default;

/// Populate the Storage object by loading an auth_table from this.filename.
/// Note that load() begins by clearing the auth_table, so that when the call
/// is complete, exactly and only the contents of the file are in the
/// auth_table.
/// 
/// *** clear auth_table field
/// 2. open file
/// 3. read auth_table from file
/// 4. populate fields in storage object with authtable
/// 
/// @returns false if any error is encountered in the file, and true
///          otherwise.  Note that a non-existent file is not an error.
bool Storage::load() {

  // clear current auth_table field so a new one can be loaded
  fields -> auth_table.clear();

  //Open file containing new auth_table
  const char* file_name = fields -> filename.c_str();
  FILE* file = fopen(file_name, "rb");

  if (file == nullptr)
  {
    cerr << "File not found: " + string(file_name) + "\n";
    return true;
  }

  // read auth_table entries until EOF
  while (!feof(file))
  {
    // 8 bytes is the number of bytes in "AUTHAUTH"
    char auth_auth[8]; 
    if (!fread(auth_auth, 8, 1, file))
    {
      cerr << "cannot read from file in load()";
      return false;
    }
    char username_len[4];
    if (!fread(username_len, 4, 1, file))
    {
      cerr << "cannot read from file in load()";
      return false;
    }
    int username_len_int = atoi(username_len);

    char username[username_len_int];
    if (!fread(username, username_len_int, 1, file))
    {
      cerr << "cannot read from file in load()";
      return false;
    }

    char passhash_len[4];
    if (!fread(passhash_len, 4, 1, file))
    {
      cerr << "cannot read from file in load()";
      return false;
    }
    int passhash_len_int = atoi(passhash_len);

    char pass_hash[passhash_len_int];
    if (!fread(pass_hash, passhash_len_int, 1, file))
    {
      cerr << "cannot read from file in load()";
      return false;
    }

    char num_bytes[4];
    if (!fread(num_bytes, 4, 1, file))
    {
      cerr << "cannot read from file in load()";
      return false;
    }
    int num_bytes_int = atoi(num_bytes);

    char content[num_bytes_int];
    if (!fread(content, num_bytes_int, 1, file))
    {
      cerr << "cannot read from file in load()";
      return false;
    }

    // create new auth table entry to insert into auth_table
    Internal::AuthTableEntry new_auth_table = 
    {
      string(username), string(pass_hash), vec_from_string(string(content))
    };

    // insert (key, value) pair into auth_table
    fields->auth_table.insert({string(username), new_auth_table});
  }

  fclose(file);
  return true;
}

/// Create a new entry in the Auth table.  If the user_name already exists, we
/// should return an error.  Otherwise, hash the password, and then save an
/// entry with the username, hashed password, and a zero-byte content.
///
/// @param user_name The user name to register
/// @param pass      The password to associate with that user name
///
/// @returns False if the username already exists, true otherwise
bool Storage::add_user(const string &user_name, const string &pass) {

  // iterate through auth_table to see if username is already taken
  for (auto map_itr = fields -> auth_table.cbegin(); 
        map_itr != fields -> auth_table.cend(); ++map_itr)
  {
    // if the username already exists in the auth table, return false
    if (!(map_itr -> first).compare(user_name))
    {
      return false;
    }
  }

  // hash password password passed to function
  unsigned char hashed_pw[128];
  MD5(reinterpret_cast<const unsigned char*>(pass.c_str()), pass.length(), hashed_pw);

  // create empty content vector 
  vec empty_content;

  // create new auth table entry to insert into auth table
  Internal::AuthTableEntry new_auth_table = 
  {
    user_name, string(reinterpret_cast<const char*>(hashed_pw)), empty_content
  };

  // add username, hashed password and empty content to auth table
  fields -> auth_table.insert({user_name, new_auth_table});

  return true;
}

/// Set the data bytes for a user, but do so if and only if the password
/// matches
///
/// @param user_name The name of the user whose content is being set
/// @param pass      The password for the user, used to authenticate
/// @param content   The data to set for this user
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          message (possibly an error message) that is the result of the
///          attempt
vec Storage::set_user_data(const string &user_name, const string &pass,
                           const vec &content) {
  // call auth to make sure user matches
  if (auth(user_name, pass))
  {
    // set content for user
    fields -> auth_table[user_name].content = content;
    // if the content is empty, return error
    if (content.size() == 0)
    {
      return vec_from_string(RES_ERR_XMIT);
    }
     return vec_from_string(RES_OK);
  }
  // if auth fails
  else
  {
    return vec_from_string(RES_ERR_LOGIN);
  }
  
}

/// Return a copy of the user data for a user, but do so only if the password
/// matches
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param who       The name of the user whose content is being fetched
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          data (possibly an error message) that is the result of the
///          attempt.  Note that "no data" is an error
pair<bool, vec> Storage::get_user_data(const string &user_name,
                                       const string &pass, const string &who) {

  // call auth to validate user
  if (auth(user_name, pass))
  {
    // if the retreived content is not empty
    vec data = fields -> auth_table[who].content;
    if (!data.size())
    {
      return {true, data};
    }
    // if the vector is not empty, return the content
    return {false, vec_from_string(RES_ERR_NO_DATA)};
  }
  // print message if auth failed
  else
  {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  }
}

/// Return a newline-delimited string containing all of the usernames in the
/// auth table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A vector with the data, or a vector with an error message
pair<bool, vec> Storage::get_all_users(const string &user_name,
                                       const string &pass) {
  
  if (auth(user_name, pass))
  {
    // get auth table
    auto current_auth_table = fields -> auth_table;
    
    // get all keys from auth table and append them to string with a trailing newline
    string usernames;
    for (auto& key_val : current_auth_table)
    {
      usernames.append(key_val.first);
      usernames.append("\n");
    }
    // return false and usernames on success
    return {false, vec_from_string(usernames)};
  }
  else
  {
    //return true and error message on failed login
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }
}

/// Authenticate a user
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns True if the user and password are valid, false otherwise
bool Storage::auth(const string &user_name, const string &pass) {

  // get auth table
  auto current_auth_table = fields -> auth_table;
  
  // iterate through auth_table
  for (auto& key_val : current_auth_table)
  {
    // if the username in the current iteration is the one passed, check password
    if (!(key_val.first).compare(user_name))
    {
      // hash password password passed to function, 128 is MD5 hash length
      unsigned char hashed_pw[128];
      MD5(reinterpret_cast<const unsigned char*>(pass.c_str()), pass.length(), hashed_pw);

      // if the hashed password that was passed matches the stored hashed password, return true
      if (!string(reinterpret_cast<char*>(hashed_pw)).compare(key_val.second.pass_hash))
      {
        return true;
      }
    }
  }
  return false;
}

/// Write the entire Storage object (right now just the Auth table) to the
/// file specified by this.filename.  To ensure durability, Storage must be
/// persisted in two steps.  First, it must be written to a temporary file
/// (this.filename.tmp).  Then the temporary file can be renamed to replace
/// the older version of the Storage object.
void Storage::persist() { 
  //get current auth table to be written to file
  auto current_auth_table = fields -> auth_table;
  
  //Open file containing new auth_table
  const char* file_name_chars = fields -> filename.c_str();

  // build full .tmp file name
  string tmp_file_name = string(file_name_chars).append(".tmp");

  // open tmp file to write to
  ofstream stream(string(tmp_file_name), ios::binary);

  // write AUTHAUTH header
  stream << "AUTHAUTH";

  // write all entries in the auth table to file
  for (auto& key_val : current_auth_table) 
  {
    // write username length
    stream << key_val.first.length();
    // write username
    stream << key_val.first;
    // write hashed password length
    stream << key_val.second.pass_hash.length();
    // write hashed password
    stream << key_val.second.pass_hash;
    // write number of bytes in content
    stream << key_val.second.content.size();
    // write content
    stream << key_val.second.content.data();
  }
  // close file when writing is done
  stream.close();

  // rename file, return print error if rename failed
  if (rename(tmp_file_name.c_str(), file_name_chars))
  {
    cerr << "could not rename file in persist()";
    return;
  }
}

/// Shut down the storage when the server stops.
///
/// NB: this is only called when all threads have stopped accessing the
///     Storage object.  As a result, there's nothing left to do, so it's a
///     no-op.
void Storage::shutdown() {}
