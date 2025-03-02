.. include:: _cdefs.rst

Glossary
========

.. glossary::

   bind mount
      ability to mount a file or directory over another file or directory
      respectively so that the mounted filesystem content may be viewed from an
      alternate mount point (see section `Creating a bind mount` of |mount(2)|
      and |mount(8)|)

   cwd
   current working directory
      working directory associated with a process that is used in the resolution
      of relative file names (see |getcwd(3)|)

   capabilities
      see |capabilities|

   credentials
      see |credentials|

   effective group
   effective user
       Identifier used by the kernel to determine the permissions that the
       process will have when accessing shared resources (see section `User and
       group identifiers` of |credentials(7)|)

   fifo
      Special file (a named pipe) similar to a |pipe|, except that it is accessed
      as part of the filesystem (see |fifo(7)|)

   file mode bits
      filesystem file mode bits expressed as an octal number (see |chmod(2)|)

   fs-major
      filesystem device file major number identifying the class of a device and
      expressed as positive integer (see |makedev(3)|)

   fs-minor
      filesystem device file minor number identifying a specific instance of a
      device and expressed as positive integer (see |makedev(3)|)

   fs-mode
      see |file mode bits|

   gid
      system group identifier expressed as an integer (see |credentials(7)| and
      |login.defs(5)|)

   groupname
      a system group name expressed as a |string| (see |group(5)| and
      |login.defs(5)|)

   host
      see |host|

   jail
      see |jail|

   named pipe
      see |fifo| and |pipe|

   namespaces
      see |namespaces|
      
   no_new_privs
      A Linux kernel flag that prevents a parent program from gaining
      privileges through calls to |execve(2)|.
      See `no_new_privs`_ for more informations.

   pathname
      a |string| that uniquely identifies a filesystem entry (see
      |path_resolution(7)|)

   pid
      process identifier (see |getpid(2)| and |credentials(7)|)
      
   pipe
      a unidirectional interprocess communication channel (see |pipe(7)|)

   process file mode creation mask
      see |umask|

   real group
   real user
       Identifier used to determine who owns a process (see section `User and
       group identifiers` of |credentials(7)|)

   supplementary groups
      a set of additional system group IDs that are used for permission checks
      when accessing files and other shared resources (see |credentials(7)|,
      |getgroups(2)| and |initgroups(3)|)

   uid
      a system user identifier expressed as in integer (see |credentials(7)| and
      |login.defs(5)|)

   umask
       |file mode bits| mask applied when a process creates a filesystem entry
       (see |umask(2)|)

   username
      a system user name expressed as a |string| (see |passwd(5)| and
      |login.defs(5)|)
