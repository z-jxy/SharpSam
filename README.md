# SharpSam
----------
This is just a small tool I wrote to get better with using c#.
The program takes a single argument, either `lsa` to dump the SAM hashes as SYSTEM, or `lsa!` as an admin to try to elevate to system by stealing a token from a SYSTEM process using DuplicateTokenEx.

Most of the hardwork for this comes from the [SharpKatz](https://github.com/b4rtik/SharpKatz) project, I just made a few changes so it doesn't need the registry files on disk to dump the hashes + the feature for elevating to system. 
#
Notes: 
- Your process must be in a high-integrity context.
- This tool was designed to be used against x64 systems as it uses x64 syscalls
