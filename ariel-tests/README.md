Portable tests for embedded-cal
===============================

This crate uses Ariel OS to make the tests for `embedded-cal` runnable easily on any hardware for which it is available.

Currently, there is no integration of `embedded-cal` into Ariel, so the required setup is part of this crate.

Running
-------

* Ensure that Ariel OS's [build dependencies are met](https://ariel-os.github.io/ariel-os/dev/docs/book/getting-started.html).

* Run:

  ```console
  $ laze build -b native run
  ```

  for native (running on your PC).

  For other concret hardware,
  find its replacement value in the [list of Ariel OS supported boards](https://ariel-os.github.io/ariel-os/dev/docs/book/boards/index.html).

* Match the type printed to indicate the embedded-cal type with your expectations.

  (On native, this should be `embedded_cal_rustcrypto::RustcryptoCal` at the moment;
  where there is hardware acceleration, it should differ).

* Observe that the output lists tests that are being run,
  and the command terminates successfully.
