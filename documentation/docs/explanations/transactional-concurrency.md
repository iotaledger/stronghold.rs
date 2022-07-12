---
description: Software Transactional Memory and Transactional Concurrency
image: /img/logo/Stronghold_icon.png
keywords:
- stm
- concurrency
- lockless
- explanation
---

# Software Transactional Memory and Transactional Concurrency


Writing software that runs on CPUs with more than one core is the norm nowadays. Software libraries heavily use concurrent code, separating sequential steps of work into concurrent, possibly parallel executed packages of work. Therefore, we need the means to synchronize the work on specific points to keep a consistent state across all threads. This section explains a relatively new approach for optimistic locking without the fear of deadlocks: software transactional memory.

## Software Transactional Memory

Today’s computing power derives from many CPU cores doing work in parallel. Any software that doesn’t use present-day concurrency will be less performant than software that does. Stronghold is no different, and Rust is an excellent programming language that offers a lot of concurrency and asynchronous primitives.


### The Actor Model

Stronghold employs a well known concurrency architecture: the actor model. The basic idea of the actor model is to have isolated actors, each taking care of some functionality. Actors receive messages with data to act upon and return data when they finish processing it. Since each actor contains its own state and concurrency is achieved by not directly calling functions but by polling messages, most of the undesirable concurrency problems are taken care of. Dead-locks will never occur. 

The actor system is almost ubiquitous in the target architecture. Many modern languages have the actor model built in with an excellent supervisor, among other tools. With Rust, the integration involves a lot of boilerplate code. But it’s for each user to decide whether or not the actor model approach is favorable. We wanted to know whether we could provide a simple interface, ideally some primitive types to work on with simple function calls, but still run in a concurrent setup without the headaches that come with locks and mutexes. 

## Software Transactional Memory (STM)

A newer approach is using Software Transactional Memory (STM). STMs have been around for quite some time. In STMs, each operation on memory happens in an atomic transaction. Whenever memory is modified, this modification is written into a log. While inside a transaction, reading from memory also is done through a log. The transaction has finished when all changes recorded inside the log have been committed to the actual memory. A transaction fails if another thread tries to modify the targeted piece of memory between operations. A failed transaction can be re-run any number of times. 

This approach guarantees that modifications to memory are always consistent, but it comes with a restriction. Since transactions can be retried, operations inside a transaction must be idempotent and should not have any side effects. In an extreme case, think of a function that launches an ICMB: you can not reverse the process. Another edge case concerning STM-based approaches is interleaving transactions, where reads and writes are alternating between two threads. In a worst-case scenario, both transactions would retry indefinitely. 

