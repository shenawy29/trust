This project is a user-space custom TCP implementation in Rust, using Jon Gjengset's TCP streams, RFC 9293, RFC 793, Computer Networks: A Top Down Approach, and a lot of documentation reading.

In order to try this project out, a Linux machine is requried, since this uses virtual TUN/TAP interfaces, which exist only on Linux.
Running the run.sh script will set everything up. Start a packet analyzer in another terminal or in a GUI, and try to communicate with the interface bound to port 9000, using Netcat, Curl, or any client running on top of TCP.

This version uses the async Tokio runtime, without any use of OS threads.
