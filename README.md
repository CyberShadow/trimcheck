# trimcheck

This program provides an easy way to test whether TRIM works on your SSD.
It uses a similar method to the one described [here][Anandtech],
but uses sector calculations to avoid searching the entire drive for the sought pattern.
It also pads the sought data with 32MB blocks of dummy data, to give some room
to processes which may otherwise overwrite the tested deteled disk area.

The program will set up a test by creating and deleting a file with unique contents,
then (on the second run) checks if the data is still accessible at the file's previous location.

   [Anandtech]: http://www.anandtech.com/show/6477/trim-raid0-ssd-arrays-work-with-intel-6series-motherboards-too/2

## Download

You can download a compiled version on my website, [here](http://files.thecybershadow.net/trimcheck/).

## Usage

Place this program file on the same drive you'd like to test TRIM on, and run it.
Administrator privileges and at least 64MB free disk space will be required.
