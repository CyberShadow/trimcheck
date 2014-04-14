# trimcheck

This program provides an easy way to test whether TRIM works on your SSD.
It uses a similar method to the one described [here][Anandtech],
but uses sector calculations to avoid searching the entire drive for the sought pattern.
It also pads the sought data with 32MB blocks of dummy data, to give some room
to processes which may otherwise overwrite the tested deleted disk area.

The program will set up a test by creating and deleting a file with unique contents,
then (on the second run) checks if the data is still accessible at the file's previous location.

   [Anandtech]: http://www.anandtech.com/show/6477/trim-raid0-ssd-arrays-work-with-intel-6series-motherboards-too/2

## Download

You can download a compiled version on my website, [here](http://files.thecybershadow.net/trimcheck/).

## Usage

Place this program file on the same drive you'd like to test TRIM on, and run it.
Administrator privileges and at least 64MB free disk space will be required.

## Building from source

A [D compiler](http://dlang.org/download.html) is required.

You can use the `rdmd` tool (included with DMD) to build `trimcheck`:

    $ git clone --recursive https://github.com/CyberShadow/trimcheck
    $ cd trimcheck
    $ rdmd --build-only trimcheck

## License

`trimcheck` is available under the [Mozilla Public License, version 2.0](http://mozilla.org/MPL/2.0/).

## Changelog

### trimcheck v0.6 (2014.03.23)

 * Fix support for drives with big clusters
 * Fix false negatives due to compressed filesystems

### trimcheck v0.5 (2013.08.21)

 * Write fully random data as padding instead of a repeating pattern (to avoid possible intervention of deduplication components)
 * Cryptographically sign executable

### trimcheck v0.4 (2013.02.18)

 * Remove read checks, as they caused tested data to not be TRIMmed in some configurations
 * Add symlink detection

### trimcheck v0.3 (2013.01.09)

 * Add support for SSDs which present cleared sectors as filled with 1s instead of 0s

### trimcheck v0.2 (2012.12.10)

 * Pad tested data with 32MB of dummy data on either side

### trimcheck v0.1 (2012.12.09)

 * Initial release
