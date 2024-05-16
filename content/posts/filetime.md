---
title: "Filetime"
date: 2024-05-16T12:14:06+02:00
tags:
  - dfir
  - windows
  - file
  - time
  - timestamp
---

# FILETIME in Windows

## What is FILETIME?

A file time is a 64-bit value that represents the number of 100-nanosecond intervals that have elapsed since 12:00 A.M. January 1, 1601 Coordinated Universal Time (UTC). The system records file times when applications create, access, and write to files.

The NTFS file system stores time values in UTC format, so they are not affected by changes in time zone or daylight saving time. The FAT file system stores time values based on the local time of the computer.

Time stamps are updated at various times and for various reasons. The only guarantee about a file time stamp is that the file time is correctly reflected when the handle that makes the change is closed.

>Not all file systems can record creation and last access times, and not all file systems record them in the same manner. For example, the resolution of create time on FAT is 10 milliseconds, while write time has a resolution of 2 seconds and access time has a resolution of 1 day, so it is really the access date. The NTFS file system delays updates to the last access time for a file by up to 1 hour after the last access.

## FILETIME Structure (minwinbase.h)

```
typedef struct _FILETIME {
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;
```

Here, the `dwLowDateTime` is the low-order and the `dwHighDateTime` is the high-order part of the file time.

>Older compilers did not have support for 64 bit types. So the structure splits the 64 bit value into two 32 bit parts. The low part contains the least significant 32 bits. The high part contains the most significant 32 bits.

## Converting FILETIME to Human Readable Format

To convert the FILETIME into human readable format we need a unsigned 64 bit integer union. But 64 bit integer support may vary compiler to compiler based on CPU architecture and OS versions. Microsoft's official documentation says it supports `ULARGE_INTEGER` (unsigned 64 bit integer union) from `Windows 10 Build 20348`.

```
typedef union _ULARGE_INTEGER {
  struct {
    DWORD LowPart;
    DWORD HighPart;
  } DUMMYSTRUCTNAME;
  struct {
    DWORD LowPart;
    DWORD HighPart;
  } u;
  ULONGLONG QuadPart;
} ULARGE_INTEGER;
```

>The ULARGE_INTEGER structure is actually a union. If your compiler has built-in support for 64-bit integers, use the QuadPart member to store the 64-bit integer. Otherwise, use the LowPart and HighPart members to store the 64-bit integer.

So, many softwares uses the LowPart and HighPart to store a unsigned 64 bit integer by splitting it into 32 bit each. For example `Notepad++` uses `originalFileLastModifTimestamp` as `LowPart` and
`originalFileLastModifTimestampHigh` as `HighPart` to store the FILETIME timestamps.

To retrieve a human readable date/time from these two parts needs some arithmatic operations.

A simplest way to get the original FILETIME timestamp from LowPart and HighPart is a by using the following formula. 

```
LowPart + 2^32 * HighPart
```

The formula does not provide a good enough precision. Meaning the retrieved value may have some deviations of minutes and seconds.

To retrive the precise date/time value we need to perform some bitwise operation on the `LowPart` and `HighPart` in python to convert it into it's original form (a 64 bit unsigned integer).

A FILETIME timestamp is a number in 100-nanosecond intervals that have elapsed since 12:00 A.M. January 1, 1601 Coordinated Universal Time (UTC) till the creation time of the timestamp. To get the creation time, we need to add it to the nanosecond value of the initial date (1601-01-01).

**PS: We can convert the timestamp's value to millisecond or second also. The retrived date/time will be in UTC, as the initial value is in UTC.**

Here's a simple python script to convert splitted FILETIME timestamp to human readable format.

```
import datetime

timestamp_low = -1354503710
timestamp_high = 31047188

full_timestamp = (timestamp_high << 32) | (timestamp_low & 0xFFFFFFFF)

print(full_timestamp)

timestamp_seconds = full_timestamp / 10**7

print(timestamp_seconds)

converted_date_from_file_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=timestamp_seconds)

print(converted_date_from_file_time)
```

## References

- [File Times](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times)
- [ULARGE_INTEGER union](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ularge_integer-r1)
- [FILETIME structure](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime)
- [What is dwLowDateTime and dwHighDateTime](https://stackoverflow.com/questions/29266743/what-is-dwlowdatetime-and-dwhighdatetime)
- [How to create FILETIME in Win32?](https://stackoverflow.com/posts/1100288/revisions)
- [HTB Discussion Board](https://forum.hackthebox.com/t/noted-sherlock/307329/6)
- [LDAP, Active Directory & Filetime Timestamp Converter](https://www.epochconverter.com/ldap)