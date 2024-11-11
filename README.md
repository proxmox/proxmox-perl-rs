# Hints for development:

With the current perlmod, the `.pm` files don't actually change anymore, since the exported method
setup is now handled by the bootstrap rust-function generated by perlmod, so for quicker debugging,
you can just keep the installed `.pm` files from the package and simply link the library to the
debug one like so:

NOTE: You may need to adapt the perl version number in this path:
```
# ln -sf $PWD/target/debug/libpve_rs.so /usr/lib/x86_64-linux-gnu/perl5/5.32/auto/libpve_rs.so
```

Then just restart pvedaemon/pveproxy after running `make pve`.

# Version Bumps

## TL;DR

- Common *code* changes -> bump the *products*, *not* the common package.
- Common *package list* changes -> bump common AND products
  (That's the `$(PERLMOD_PACKAGES)` list in `common/pkg/Makefile`)
- On breaking changes to the common code, both PVE and PMG should be bumped along with the common
  package which should declare its `Depends`/`Breaks` accordingly.

## The `common` package.

This package only provides the "list" of packages the common code contains, but does not by itself
provide a *library*. In other words, this only provides a bunch of `.pm` files which cause whichever
product-specific library is available to be loaded.

The rust code in the common directory is compiled as part of the product libraries. Those libraries
actually provide both the product specific as well as the common perl "packages" via the library.

## The product packages.

These are the actual libraries. Their source code both "include" the `common` rust code by way of a
symlink (but when a source package is created, that symlink is replaced by a *copy* of the common
dir), so building them locally with `cargo build` should use the `common` code from git.

These provide the actual *functionality* the `common` package declares to exist (via its `.pm`
files), in addition to the product specific parts.
