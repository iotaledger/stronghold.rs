---
description: Stronghold as a concurrent software
image: /img/logo/Stronghold_icon.png
keywords:
- stm
- concurrency
- lockless
- explanation
---

# Concurrency in Stronghold

Writing software that runs on CPUs with more than one core is the norm nowadays. Software libraries heavily use concurrent code, separating sequential steps of work into concurrent, possibly parallel executed packages of work.
Writing concurrent programs makes the most of our current computers and servers in terms of performance. The downsides of such approach is that it is difficult to write such programs without having bugs. This is mostly due to a problem called _data race_ where multiple threads temper the same shared memory at the same time. This may create inconsistent behaviour of the concurrent program due to the fact that each thread executes its computations in a non-deterministic order.
Multiple solutions to tackle concurrent programming exist and we have been exploring them for Stronghold.
In the following sections we will present you different solutions that have been tested to have Stronghold as a concurrent library.

## The Actor Model

Stronghold employs a well known concurrency architecture: the actor model. The basic idea of the actor model is to have isolated actors, each taking care of some functionality. Actors receive messages with data to act upon and return data when they finish processing it. Since each actor contains its own state and concurrency is achieved by not directly calling functions but by polling messages, most of the undesirable concurrency problems are taken care of. Dead-locks will never occur. 

The actor system is almost ubiquitous in the target architecture. Many modern languages have the actor model built in with an excellent supervisor, among other tools. With Rust, the integration involves a lot of boilerplate code. But it’s for each user to decide whether or not the actor model approach is favorable. We wanted to know whether we could provide a simple interface, ideally some primitive types to work on with simple function calls, but still run in a concurrent setup without the headaches that come with locks and mutexes. 

### Why didn't we keep the actor model?

First iteration of Stronghold with the actor model was done with the rust crate called [Riker](https://riker.rs/) actor system crate. 
Unfortunately this crate was discontinued we had to find an alternative which was the [Actix](https://github.com/actix/actix) actor framework crate.
Actix uses the Tokio runtime which came as an issue for us as the Stronghold library. 
Indeed software using Stronghold had to pass ownership of the runtime to our code when making function calls to the Stronghold library.
This was cumbersome for our users and we abandoned the idea of using the actor model for concurrent programming and explored other paradigms.


## Software Transactional Memory (STM) with Transactional Locking 2 (TL2)

A newer approach is using Software Transactional Memory (STM). STMs have been around for quite some time. In STMs, each operation on memory happens in an atomic transaction. Whenever memory is modified, this modification is written into a log. While inside a transaction, reading from memory also is done through a log. The transaction has finished when all changes recorded inside the log have been committed to the actual memory. A transaction fails if another thread tries to modify the targeted piece of memory between operations. A failed transaction can be re-run any number of times. 

This approach guarantees that modifications to memory are always consistent, but it comes with a restriction. Since transactions can be retried, operations inside a transaction must be idempotent and should not have any side effects. In an extreme case, think of a function that launches an ICMB: you can not reverse the process. Another edge case concerning STM-based approaches is interleaving transactions, where reads and writes are alternating between two threads. In a worst-case scenario, both transactions would retry indefinitely. 

### TL2

Implementation of TL2 is inspired from these papers [1](https://citeseer.ist.psu.edu/viewdoc/summary?doi=10.1.1.90.811&rank=4&q=various%20cross%20version%20operation&osm=&ossid=) and [2](https://www.researchgate.net/publication/220854689_Testing_patterns_for_software_transactional_memory_engines).

The idea is quite straightforward. A global clock is used and incremented every time a transaction terminates. 
Shared memory/variables are tagged with a local clock value corresponding to the moment they were last modified by a transaction commitment.
Transactions are computed on copies of these shared memory/variables.
At the end of each transaction the system needs to check that all the shared memory/variables used during the transaction have not been tampered by another transaction to keep a consistent behaviour. 
To check such thing the local clock of the copies used for the transaction are checked against the local clock of the original shared memory/variables.
If the check detect any inconsistency between clock values then the transaction is reset and computed again.
If the check is successful the copies are committed and replace the original shared memory/variables and they are also given a new local clock value by the global clock.

This approach advantage is that the idea is relatively simple and implement the STM model. The downside is that the implementation we developed of TL2 is painfully slow and usually going single thread is faster than using multiple threads. 
We suspect that this poor performance are due to multiple interleaving of threads which force the transactions to be reset multiple times. Further investigation is required to confirm this idea.


## Read-Log-Update (RLU)

RLU is an extension of the more famous _Read-Copy-Update_ (RCU) that has been widely adopted in the Linux kernel.

RLU was first presented in 2015 in the paper [Read-Log-Update: A Lightweight Synchronization Mechanism for Concurrent Programming](http://sigops.org/sosp/sosp15/current/2015-Monterey/printable/077-matveev.pdf). 

Contrary to TL2 previously presented, RLU is a blocking algorithm.
Threads do their computations locally and synchronize with each other using their local clock (when the computations started) and a common global clock.
A thread logs the new value of any shared memory that it has modified.
To read shared memory a thread either does it directly in the memory or go fetch it in another thread logs when it has been locked and is being modified.
When a thread wants to commit its computations to the memory it has to wait that all the other threads that have started with an old memory state to terminate beforehand.
The upside of such approach is that a thread never needs to redo its computation since it has waited the correct timing to commit its work.
In return threads have to spend some time idle since they have to wait. 
However the whole RLU algorithm is lock-free meaning that at any moment there is always a thread that advances in its computation and the whole system cannot be hard stuck.

## Concurrent programming with locks

Using locks is one of the most basic approach to concurrent programming. 
Lock are used to control the access to shared memory/variables. Depending of the type of locks used you can restrict the access to a shared memory/variable to either one or a limited number of threads. 
This prevents data race since the different threads cannot access the shared memory/variables in a chaotic way. 
The biggest issue is that those locks are in general difficult to use correctly and really hard to debug. 
One of the most problematic situation that can happen with locks are __deadlocks__. 
Deadlocks happen when the whole system cannot advance anymore due to the fact that different threads require some locks to advance their computation but these locks are kept and blocked by other threads in a similar situation.
Models like the actor system or the STM have been created to use locks as little as possible.

In our case the API of Stronghold is relatively straightforward therefore we're exploring the idea of using basic locks instead of a resource heavy concurrent framework.
