
# authd

authd is a token-based authentication micro-service.

## Build

`authd` is written in Crystal and uses `build.zsh` as Makefile generator, as
well as shards to fetch dependencies.

You’ll need the following tools to build authd:

  - crystal
  - shards
  - build.zsh
  - make

To build authd, run the following commands:

```
shards install
make
```

Note that if you clone authd from its repository, its `Makefile` may be missing.
In such situations, run `build.zsh -c` to generate it, after which `make` should run fine.

## Deployment

```
$ authd --help
usage: authd [options]
    -s directory, --storage directory
                                     Directory in which to store users.
    -k file, --key-file file         JWT key file
    -R                               --allow-registrations
    -h, --help                       Show this help
$
```

### Users storage

The storage directory will default to `./storage`.

No SQL database, database management system or other kind of setup is required to run authd and store users.

To migrate an instance of authd, a simple copy of the storage directory will be enough.
Make sure your copy preserves symlinks, as those are extensively used.

### Administrating users

The `authd-user-add` and `authd-user-allow` are tools to add users to authd’s database and to edit their permissions.

The permission level `none` can be used in `authd-user-allow` to remove a permission.

### Key file

authd will provide users with cryptographically signed tokens.
To sign and check those tokens, a shared key is required between authd and services using authd.

authd reads that key from a file to prevent it being visible on the command line when running authd.

Any content is acceptable as a key file.

Example:

```
$ echo "I am a key." > key-file
$ authd -k ./key-file
```

## APIs

### Protocol

authd’s protocol is still subject to change.

### Libraries

A `AuthD::Client` Crystal class is available to build synchronous clients in Crystal.

```crystal
require "authd"

authd = AuthD::Client.new
authd.key = File.read("./some-file").chomp

pp! r = authd.get_token?("login", "password")

pp! r = authd.add_user("login", "password")

pp! u = authd.get_user?("login", "password").not_nil!
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

