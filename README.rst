=============================
System Call Interposer
=============================
:Info: A system call interposer within the kernel using kprobes.
:Authors: Yoel Ivan, William Morlan, Christopher Wang


About
=====
Project 1 for CS 3210 @ Georgia Institute of Technology, Fall 2015 (M. Wolf).

Compile/Run kprobes
===================
- cd into this directory
- run the make command::

  $ make

- then insert the kprobes::

  $ sudo insmod kp_ex2.ko

- It is toggled off by default, to turn on logging, write 1 to the TOGGLE procfs file::

  $ sudo echo 0 > /proc/sysmon_toggle

- To set a user id to be logged, write the id to the UID procfs file::

  $ sudo echo [uid] > /proc/sysmon_uid

- To read out the log, read the sysmon_log procfs file::

  $ cat /proc/sysmon_log


Compile/Run test programs
=========================
- use gcc to compile and run the test_1.c, test_execve.c, and test_rogue.c