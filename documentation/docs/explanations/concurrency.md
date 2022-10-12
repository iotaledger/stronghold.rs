---
description: Learn about Stronghold as a concurrent software, the actor model STM with TL2 and RLU. 
image: /img/logo/Stronghold_icon.png
keywords:
- actor model
- rlu
- STM
- concurrency
- lockless
- explanation
---

# Concurrency in Stronghold

Writing software that runs on CPUs with more than one core is the norm nowadays. Software libraries heavily use concurrent code, separating sequential steps of work into concurrent, possibly parallel, work packages.

Writing concurrent programs makes the most of our current computers and servers in terms of performance. The downside of this approach is that it is difficult to write such programs without having bugs. This is mostly due to a problem called _data race_, where multiple threads simultaneously tamper with the same shared memory, which may create inconsistent behavior of the concurrent program because each thread executes its computations in a non-deterministic order.

Multiple solutions to tackle concurrent programming exist, and we have been exploring them for Stronghold.
In the following sections, we will present different solutions tested to make Stronghold a concurrent library.

## The Actor Model

Stronghold employed a well-known concurrency architecture: the actor model. The basic idea of the actor model is to have isolated actors, each taking care of some functionality. Actors receive messages with data to act upon and return data when they finish processing it. Since each actor contains its own state and concurrency is achieved by not directly calling functions, but by polling messages, most undesirable concurrency problems are taken care of. Deadlocks will never occur.

The actor system is almost ubiquitous in the target architecture. Many modern languages have a built-in actor model with an excellent supervisor, among other tools. With Rust, the integration involves a lot of boilerplate code. But it’s for each user to decide whether or not the actor model approach is favorable. We wanted to know whether we could provide a simple interface, ideally some primitive types to work on with simple function calls, but still run in a concurrent setup without the headaches that come with locks and mutexes.

### Why didn't we keep the actor model?

The first iteration of Stronghold implemented the actor model with the rust crate [Riker](https://riker.rs/), an actor system crate.

Unfortunately, since this crate was discontinued, we had to find an alternative: the [Actix](https://github.com/actix/actix) actor framework crate.
Actix uses the Tokio runtime, which came as an issue for us as the Stronghold library.

Software using Stronghold had to pass ownership of the runtime to our code when making function calls to the Stronghold library.
This was cumbersome for our users, and we abandoned the idea of using the actor model for concurrent programming and explored other paradigms.


## Software Transactional Memory (STM) with Transactional Locking 2 (TL2)

STMs have been around for quite some time. In STMs, each operation on memory happens in an atomic transaction. Whenever memory is modified, this modification is written into a log. While inside a transaction, reading from memory is also done through a log. The transaction has finished when all changes recorded inside the log have been committed to the actual memory. A transaction fails if another thread tries to modify the targeted piece of memory between operations. A failed transaction can be re-run any number of times.

This approach guarantees that modifications to memory are always consistent, but it comes with a restriction. Since transactions can be retried, operations inside a transaction must be idempotent and should not have any side effects. In an extreme case, think of a function that launches an ICMB: you can not reverse the process. Another edge case concerning STM-based approaches is interleaving transactions, where reads and writes are alternating between two threads. In a worst-case scenario, both transactions would retry indefinitely.

### TL2


The Implementation of TL2 is inspired by these papers:

* [Transactional Locking II (2006)](https://citeseer.ist.psu.edu/viewdoc/summary?doi=10.1.1.90.811&rank=4&q=various%20cross%20version%20operation&osm=&ossid=)
* [Testing patterns for software transactional memory engines](https://www.researchgate.net/publication/220854689_Testing_patterns_for_software_transactional_memory_engines).

The idea is quite straightforward. A global clock is used and incremented every time a transaction terminates.
Shared memory/variables are tagged with a local clock value corresponding to the moment they were last modified by a transaction commitment.
Transactions are computed on copies of these shared memory/variables.

At the end of each transaction, the system needs to check that all the shared memory/variables used during the transaction have not been tampered with by another transaction to keep a consistent behavior.
Stronghold verifies this by checking the local clock of the copies used for the transaction against the local clock of the original shared memory/variables.

If the check detects any inconsistency between clock values, then the transaction is reset and computed again.

If the check is successful, the copies are committed and replace the original shared memory/variables, and the global clock also gives them a new local clock value.

This approach's advantage is that the idea is relatively simple and implements the STM model. The downside is that the implementation we developed of TL2 is painfully slow, and usually going single thread is faster than using multiple threads.
We suspect this poor performance is due to multiple interleaving of threads which force the transactions to be reset multiple times. Further investigation is required to confirm this idea.


## Read-Log-Update (RLU)

RLU is an extension of the more famous _Read-Copy-Update_ (RCU) that has been widely adopted in the Linux kernel.

RLU was first presented in 2015 in the paper [Read-Log-Update: A Lightweight Synchronization Mechanism for Concurrent Programming](http://sigops.org/sosp/sosp15/current/2015-Monterey/printable/077-matveev.pdf). 

Contrary to [TL2](#tl2), RLU is a blocking algorithm.
Threads do their computations locally and synchronize with each other using their local clock (when the computations started) and a common global clock.
A thread logs the new value of any shared memory it has modified.

To read shared memory, a thread either does it directly in the memory or fetches it in another thread logs when it has been locked and is being modified.
When a thread wants to commit its computations to the memory, it has to wait for all the other threads that have started with an old memory state to terminate.

The upside to this approach is that a thread never needs to redo its computation since it has to wait for the correct timing to commit its work.

In return, threads may be idle for some time as they have to wait.
However, the whole RLU algorithm is lock-free. This means that at any moment there is always a thread that advances in its computation, and the whole system cannot be hard-stuck.

## Concurrent Programming with Locks

Using locks is one of the most basic approaches to concurrent programming.
Locks are used for controlling access to shared memory/variables. Depending on the type of locks used, you can restrict access to a shared memory/variable to either one or a limited number of threads.
This prevents data race since the different threads cannot access the shared memory/variables chaotically.
The biggest issue is that those locks are generally difficult to use correctly and hard to debug.

One of the most problematic situations with locks is a __deadlock__.
Deadlocks happen when the whole system cannot advance anymore because different threads require some locks to advance their computation, but these locks are kept and blocked by other threads in a similar situation.
Models like the [actor system](#the-actor-model) or the [STM](#software-transactional-memory-stm-with-transactional-locking-2-tl2) use locks as little as possible.

In our case, Stronghold’s API is relatively straightforward, so we're exploring the idea of using basic locks instead of a resource-heavy concurrent framework.
