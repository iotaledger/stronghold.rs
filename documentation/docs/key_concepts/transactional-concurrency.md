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

#### Authors: Matthias Kandora - \<matthias.kandora@iota.org>

***Abstract:***

Writing software that runs on CPUs with more than one core is the norm today. Software libraries make heavy use of concurrent code, separating sequential steps of work into concurrent, possibly parallel executed packages of work. We therefore need the means to synchronize the work on certain points to keep a consistent state across all threads. This entry explains the concept of a rather new approach for optimistic locking without the fear of deadlocks: software transactional memory.

***In-Depth-Description:***

Today’s computing power derives from many cpu cores doing work in parallel. Any software that doesn’t make use of present-day concurrency would perform less well when compared to software that does. Stronghold is no different, and Rust is an excellent progrmaming language that offers a lot of concurrency as well as asynchronous primitives.

Stronghold employed a well known concurrency architecture: the actor model. The basic idea of the actor model is to have isolated actors, each taking care of some functionality. Actors receive messages with data to act upon, and send data back when they are finished processing it. Since each actor contains its own state and concurrency is achieved by not directly calling functions, but polling messages, most of the undesirable concurrency problems are gone. Dead-locks will never occur. But integrating an actor system makes it very much present in the target architecture. As other languages (for example, elixir) have the actor model pretty much baked in with an excellent supervisor etc, with Rust the integration involves a lot of boilerplate code. But it’s for each user to decide whether the actor model approach is favorable or not. The question we wanted to answer was whether we could provide a simple interface, ideally some primitive types to work on with simple function calls, yet still able to run in a concurrent setup without the headaches that comes with locks and mutexes. 

A newer approach would be Software Transactional Memory (STM). What is it and how does it solve the problem? STMs have been around for quite some time. The main idea is that each operation on memory happens in an atomic transaction. Whenever memory is modified, this modification is written into a log. While inside a transaction, reading from memory also is done through a log. The transaction has finished, when all changes recorded inside the log have been committed to the actual memory. A transaction fails, if between own operations another thread tries to modify the targeted piece of memory. A failed transaction can be re-run any number of times. 

This approach guarantees that modifications on memory are always consistent, but it comes with a restriction. Since transactions can be retried, operations inside a transaction necessarily need to be idempotent and shouldn’t have any side effects. In an extreme case think of a function that launches an ICMB: you simply can’t reverse the process. Another edge case concerning STM-based approaches are interleaving transactions, where reads and writes are alternating between two threads. In a worst-case scenario both transactions would retry indefinitely. 
