#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

/// ConcurrentHashTable is a concurrent hash table (a Key/Value store).  It is
/// not resizable, which means that the O(1) guarantees of a hash table are lost
/// if the number of elements in the table gets too big.
///
/// The ConcurrentHashTable is templated on the Key and Value types
///
/// The general structure of the ConcurrentHashTable is that we have an array of
/// buckets.  Each bucket has a mutex and a vector of entries.  Each entry is a
/// pair, consisting of a key and a value.  We can use std::hash() to choose a
/// bucket from a key.
template <typename K, typename V> class ConcurrentHashTable {

// create bucket structure
struct Bucket {
  std::mutex lock;
  std::vector< std::pair<K, V> > pair_vec;
};

public:

  // initialize empty bucket vector
  std::vector<Bucket> buckets;
  

  /// Construct a concurrent hash table by specifying the number of buckets it
  /// should have
  ///
  /// @param _buckets The number of buckets in the concurrent hash table
  ConcurrentHashTable(size_t _buckets) : buckets(_buckets) {}

  /// Clear the Concurrent Hash Table.  This operation needs to use 2pl
  void clear() {

    // // clear all elements from each bucket
    // for(auto& bucket : this->buckets)
    // {
    //   std::unique_lock<std::mutex> unq_lock (bucket.lock);
    //   bucket.pair_vec.clear();
    // }

    // // unlock all locks
    // for(auto& bucket : this->buckets)
    // {
    //   unq_lock.unlock();
    // }
  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key The key to insert
  /// @param val The value to insert
  ///
  /// @returns true if the key/value was inserted, false if the key already
  /// existed in the table
  bool insert(K key, V val) { 

    size_t bucket_num = get_bucket_num(key);

    std::lock_guard<std::mutex> guard (this->buckets[bucket_num].lock);
    
    // if key already exists, return false
    if (find_key(key, bucket_num) != -1)
    {
      return false;
    }

    // create new key, val pair and insert it into the bucket
    std::pair<K, V> new_entry(key, val);
    this->buckets[bucket_num].pair_vec.push_back(new_entry);

    return true;
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key The key to upsert
  /// @param val The value to upsert
  ///
  /// @returns true if the key/value was inserted, false if the key already
  ///          existed in the table and was thus updated instead
  bool upsert(K key, V val) { 

    size_t bucket_num = get_bucket_num(key);

    std::lock_guard<std::mutex> guard (this->buckets[bucket_num].lock);

    // if the key does not exist, call insert and return true
    int key_index;
    if ((key_index = find_key(key, bucket_num)) != -1)
    {
      insert(key, val);
      return true;
    }

    // the key already exists so update the key's value 
    // and return false
    this->buckets[bucket_num].pair_vec[key_index].second = val;
    return false;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @returns true if the key existed and the function was applied, false
  ///          otherwise
  bool do_with(K key, std::function<void(V &)> f) {
    
    size_t bucket_num = get_bucket_num(key);

    std::lock_guard<std::mutex> guard (this->buckets[bucket_num].lock);
    
    // if the key exists, apply function to value and return true
    int key_index;
    if ((key_index = find_key(key, bucket_num)) != -1)
    {
      this->buckets[bucket_num].pair_vec[key_index].second = 
                                f(this->buckets[bucket_num].pair_vec[key_index].second);
      return true;
    }

    // the key does not exist so return false
    return false; 
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @returns true if the key existed and the function was applied, false
  ///          otherwise
  bool do_with_readonly(K key, std::function<void(const V &)> f) {

    size_t bucket_num = get_bucket_num(key);

    std::lock_guard<std::mutex> guard (this->buckets[bucket_num].lock);

    int key_index;
    // if the key dosent exist, return false
    if ((key_index = find_key(key, bucket_num)) == -1)
    {
      return false;
    }

    // get the val and pass it to the function
    V val = this->buckets[bucket_num].pair_vec[key_index].second;
    f(val);

    // unlock and return true
    return true;
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key The key whose mapping should be removed
  ///
  /// @returns true if the key was found and the value unmapped, false otherwise
  bool remove(K key) {

    size_t bucket_num = get_bucket_num(key);

    std::lock_guard<std::mutex> guard (this->buckets[bucket_num].lock);

    // if the key exists, remove the pair and return true
    int key_index;
    if ((key_index = find_key(key, bucket_num) != -1))
    {
      this->buckets[bucket_num].pair_vec.erase(this->buckets[bucket_num].pair_vec.begin()
                                                             + key_index);
      return true;
    }

    // there is no key to remove the value, unlock
    // and return false
    return false;
  }

  /// Apply a function to every key/value pair in the ConcurrentHashTable.  Note
  /// that the function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  void do_all_readonly(std::function<void(const K, const V &)> f,
                       std::function<void()> then) {

    // // for each pair in each bucket, apply function to val
    // for (auto& bucket : this->buckets)
    // {
    //   std::unique_lock<std::mutex> unq_lock (buckets.lock);
    //   // lock each bucket before applying function
    //   unq_lock.lock();
    //   // call function on all key, val pairs
    //   for (auto& pair : bucket.pair_vec)
    //   {
    //     K key = pair.first;
    //     V val = pair.second;
    //     f(key, val);
    //   }
    // }

    // // call then before unlocking locks
    // then();

    // // unlock all locks for 2phase locking
    // for(auto& bucket : this->buckets)
    // {
    //   std::unique_lock<std::mutex> unq_lock (bucket.lock);
    //   unq_lock.unlock();
    // }                     
  }

  
  // get bucket number of key
  size_t get_bucket_num(K key) {
    
    // hash key and mod by bucketsize to get bucket number
    // for key
    std::hash<K> hasher;
    size_t bucket_num = hasher(key) % this->buckets.size();

    return bucket_num;
  }

  // returns index of key if the key already exists in the hashtable
  // returns -1 if the key does not exist
  int find_key(K key, size_t bucket_num) {

    // get size of current bucket
    int bucket_size = this->buckets[bucket_num].pair_vec.size();

    // if the key exists in the bucket, return the key's index
    for (int i = 0; i < bucket_size; i++)
    {
      K key_check = this->buckets[bucket_num].pair_vec[i].first;
      if (key == key_check)
      {
        return i;
      }
    }
    // if the key does not exist in the bucket, return -1
    return -1;
  }

  // return true if key exists and false if it does not
  bool does_key_exist(K key) {

    size_t bucket_num = get_bucket_num(key);

    // get size of current bucket
    int bucket_size = this->buckets[bucket_num].pair_vec.size();

    // if the key exists in the bucket, return the key's index
    for (int i = 0; i < bucket_size; i++)
    {
      K key_check = this->buckets[bucket_num].pair_vec[i].first;
      if (key == key_check)
      {
        return true;
      }
    }
    // if the key does not exist in the bucket, return -1
    return false;
  }
};