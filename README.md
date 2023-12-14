## HPKE over TCP using rust-hpke

# Note
As we are a group of five people, our implementation does include a setup over
TCP. Running the test-vectors provided by RFC-9180 in rust is comparably hard,
as most of the necessary primitives are kept private by the crates used.
Nevertheless if you want to run the test-vectors clone the rust-hpke repository
and run ``cargo test --all-features``. Forking and changing the original
repository to gain access is possible, but we decided against it as it was only
adding file reading and writing logic to existing code. We focused instead on
our TCP implementation. But if that doesn't fit the expectation we can of course
add that afterwards.

# Structure
The cargo workspace is divided in three crates, consisting of ``client``, ``server`` and
``shared``. The latter does abstract over any external dependencies (eg. hpke-rust) 
We would recommend starting with the ``server`` and ``client`` as this is the
most straight-forward code and only than take a look at ``shared``


# Running the implementation
Please make sure that you have the rust tool-chain before moving on. 

The naming of the crates does represent the expected content. The server must be
started before the client, otherwise the client will fail with an error. 
To start those, head into the corresponding crate and execute ``cargo run``. You
can optionally add the ``--release`` flag for improved performance, but that
shouldn't make any difference for our simple use case.

If you encounter any ambiguities don't hesitate to reach out to us!



