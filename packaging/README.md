Package manager publishing templates
====================================

Tagged releases build `.deb` and `.rpm` artifacts through GoReleaser.

Homebrew and AUR should build from source for now because the CLI uses
go-sqlite3, which requires CGO for SQLite-backed features. The current release
archive build remains `CGO_ENABLED=0` to preserve existing cross-platform
archive generation, so do not publish those archives as Homebrew or AUR binary
packages until the release build is moved to CGO-capable cross builds or the
SQLite driver is migrated to a pure-Go implementation.

Publishing checklist:

1. Create a tag such as `v2.0.0`.
2. Compute the GitHub source tarball SHA256:
   `curl -L https://github.com/KKingZero/Zypheron-CLI/archive/refs/tags/v2.0.0.tar.gz | sha256sum`
3. Replace `@VERSION@` and `@SOURCE_SHA256@` in the templates.
4. Publish `homebrew/Formula/zypheron.rb.template` to `KKingZero/homebrew-zypheron`.
5. Publish `aur/PKGBUILD.template` to the `zypheron` AUR package.
