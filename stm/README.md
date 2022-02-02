# Stronghold Asynchronous Software Transactional Memory

This crate provides an implementation of a commit-time locking software transaction memory (STM). The implementation makes use of `BoxedMemory` for all relevant memory allocations where sensitive data is involved. The amount of time sensitive data is exposed in plain memory is therefore reduced to a minimum, making the STM an ideal framework to work in concurrent setups.

## Overview

Software transactional memory is of high interest in researching lock-free concurrent systems. The main idea is, that each operation on shared memory is done within a transaction. If the transaction - an execution of read and write operations - is successful, it gets commited, the value will be changed. Transactions themselves are isolated, consistent, and atomic. 

## Implementation
- 


## Integration With Stronghold


## TODO / Questions
- In an extreme case two transactions want to write to the same location, which would result in a permanent dead lock of each transaction. Is there a way to detect writes to the same location, which would result in an error?
- Could a Transaction = Future? 
- Problem: blocking Futures while processing? How-To? Another Future could wrape the execution, block advancing until a signal has been send. Returning the internal future to advance

# Issues
- 

# Resources