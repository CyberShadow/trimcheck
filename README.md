# trimcheck

This program provides an easy way to test whether TRIM works on your SSD.
It uses the same general method described [here][Anandtech],
but uses sector calculations to avoid searching the entire drive for the sought pattern.

The program will set up a test by creating and deleting a file with unique contents,
then (on the second run) checks if the data is still accessible at the file's previous location.

   [Anandtech]: http://www.anandtech.com/show/6477/trim-raid0-ssd-arrays-work-with-intel-6series-motherboards-too/2

## Usage

Place this program file on the same drive you'd like to test TRIM on, and run it.
Administrator privileges will be required.
