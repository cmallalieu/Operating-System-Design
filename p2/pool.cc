#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <unistd.h>
#include <vector>

#include "pool.h"

using namespace std;

/// thread_pool::Internal is the class that stores all the members of a
/// thread_pool object. To avoid pulling too much into the .h file, we are using
/// the PIMPL pattern
/// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
struct thread_pool::Internal {
    
    vector<thread> workers;

    queue<int> sockets;

    mutex lock;

    atomic<bool> is_shutdown = false;

    condition_variable cv;

    int num_threads;

    function<void()> shutdown_handler;
    function<bool(int)> handler_func;

  /// construct the Internal object by setting the fields that are
  /// user-specified
  ///
  /// @param handler The code to run whenever something arrives in the pool
  Internal(int size, function<bool(int)> handler) {
    
    num_threads = size;

    for (int i = 0; i < num_threads; i++)
    {
      // push workers to vector and run lambda
      workers.push_back(std::thread([&]() {
        while (true) {
          int sd = -1;
          auto unq_lock = std::unique_lock<std::mutex>(lock);
          // if sockets has a socket in it
          if (!sockets.empty()) {
            sd = sockets.front();
            sockets.pop();
          }
          // if there are no sockets and all tasks are finished
          else if (is_shutdown) 
          {
            unq_lock.unlock();
            return;
          } 
          else 
          {
            while (sockets.empty()) 
            {
              cv.wait(unq_lock); //thread will sleep and mtx will automatically unlock at once
            }
          }
          unq_lock.unlock();
          if (sd != -1) {
            bool shutdownPool = handler_func(sd);
            close(sd);

          if (shutdownPool) 
          {
            shutdown_handler();
            is_shutdown = true;
          }
        }
      }
    }));
  }
  }
};

/// construct a thread pool by providing a size and the function to run on
/// each element that arrives in the queue
///
/// @param size    The number of threads in the pool
/// @param handler The code to run whenever something arrives in the pool
thread_pool::thread_pool(int size, function<bool(int)> handler)
    : fields(new Internal(size, handler)) {}

/// destruct a thread pool
thread_pool::~thread_pool() = default;

/// Allow a user of the pool to provide some code to run when the pool decides
/// it needs to shut down.
///
/// @param func The code that should be run when the pool shuts down
void thread_pool::set_shutdown_handler(function<void()> func) {
  fields->shutdown_handler = func;
}

/// Allow a user of the pool to see if the pool has been shut down
bool thread_pool::check_active() { 
  return fields->is_shutdown; 
}

/// Shutting down the pool can take some time.  await_shutdown() lets a user
/// of the pool wait until the threads are all done servicing clients.
void thread_pool::await_shutdown() {

  std::lock_guard<std::mutex> guard (fields->lock);

  //change flag to done
  fields->is_shutdown = true;

  // signal all threads 
  fields->cv.notify_all();

  // join all threads that are joinable
  for (auto& thread : fields->workers)
  {
    if (thread.joinable())
    {
      thread.join();
    }
  }

  fields->shutdown_handler();
}

/// When a new connection arrives at the server, it calls this to pass the
/// connection to the pool for processing.
///
/// @param sd The socket descriptor for the new connection
void thread_pool::service_connection(int sd) {

  std::lock_guard<std::mutex> guard (fields->lock);

  // push new sd job into queue
  fields->sockets.push(sd);

  // signal waiting threads that there is a new job
  fields->cv.notify_one();
}
