# SharpSam
----------
This is just a small tool I wrote to get better with using c#.
You can pass either 'lsa' to dump the SAM hashes as SYSTEM.
Or you can run with 'lsa!' as an admin to try to elevate to system by stealing a token from a SYSTEM process using DuplicateTokenEx.
#
Note: This tool was designed to be used against x64 systems as it uses x64 syscalls
