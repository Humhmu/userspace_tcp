TCP and IP together form the foundation of most Internet communication: IP handles addressing and routing packets from source to destination, while TCP layers reliability and connection management on top.

This project will implement TCP and IP from scratch in Linux user-space, using a TUN/TAP virtual network interface to intercept and inject raw packets without modifying the kernel's own networking stack. The resulting implementation should be capable of interacting with real, unmodified TCP/IP stacks (e.g. establishing a connection with a standard Linux host, transferring data reliably, and correctly handling loss).

Project goals: 
1) Understand the TCP and IP in enough depth to implement them correctly
2) Design and build a user-space IP and TCP stack using a TUN/TAP interface
3) Validate the implementation against existing stacks, and evaluate its performance

This project will be implemented primarily in Rust.
