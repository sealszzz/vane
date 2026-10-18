# Third-party notices

Official Vane release binaries statically link the following upstream
projects:

- AWS-LC: <https://github.com/aws/aws-lc>. AWS-LC combines code under several
  licenses, as described by its exact upstream `LICENSE` and `NOTICE` files.
- json-c: <https://github.com/json-c/json-c>. json-c is distributed under the
  MIT license described by its upstream `COPYING` file.

The release build copies the exact upstream license and notice files from the
resolved dependency source trees into binary packages under
`third_party/licenses/`. Each binary package also contains a `DEPENDENCIES`
file recording the exact dependency tags and Git commits used for that build.

Vane itself is distributed under the MIT License in [LICENSE](LICENSE).
