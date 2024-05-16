---
title: "Master File Table"
date: 2024-05-16T11:20:29+02:00
tags:
  - dfir
  - windows
  - master
  - file
  - table
---

## What is a Master File Table?

The Master File Table (MFT) is a system file in the NTFS file system (having the name $MFT) that stores metadata information about all files and directories on an NTFS volume. The MFT acts as an index to all the files and directories on the volume, providing quick access to the information needed to retrieve a file.

Each file and directory on an NTFS volume has a unique record in the MFT, known as an MFT entry. The MFT entry contains information such as the file name, timestamps, permissions, and a pointer to the file’s data. The corresponding MFT entry is updated when a file is created or modified.

When a file is deleted, the corresponding MFT entry is marked as free, but the actual file data remains on the disk until it is overwritten by new data. This can be useful in data recovery scenarios, as the deleted file’s data may still be recoverable. Successful data recovery requires that the Disk regions occupied by the deleted data are not overwritten. 

**Note: The MFT is stored on the NTFS volume and is an important component of the NTFS file system. The MFT must remain intact and undamaged for the file system to function properly.**

## Why is the MFT Useful for Forensics?

1. **Comprehensive Data Storage**: The MFT provides a detailed record of each file, including
timestamps, permissions, and data content locations, making it invaluable for forensic
investigations.

2. **Recovery of Deleted Files**: Even when files are deleted, their MFT entries might not be
immediately reused. This allows forensic analysts to recover details about the deleted files,
which can be crucial in legal contexts.

3. **Tracking File Modifications**: The MFT includes multiple timestamps that record different
types of file access and modifications. This can help construct a timeline of activities on a
system, an essential aspect of forensic analysis.

4. **Detecting Malware and Unauthorized Access**: Since the MFT records file creation and
modification details, unusual changes detected in these entries can indicate unauthorised
access or malware activity.

## General Structure of MFT Record

The structure of the Master File Table (MFT) in the NTFS file system is complex and consists of multiple records, each of which represents a file or directory on the NTFS volume. Each MFT record is 1024 bytes, making the MFT very simple to parse. An MFT record has the following general structure:

- **File Record Header**: This section contains information about the record itself, including the size of the record, the offset of the update sequence, and the flags that indicate the state of the file or directory.
    
- **File Attribute List**: This section contains a list of attributes that describe the file or directory, including its name, timestamps, size, and data. Each attribute is stored as a separate structure with its format.
    
- **Data Runs**: This section describes the location of the file or directory’s data on the disk. The data runs are stored as a series of extents describing the starting cluster and the length of each contiguous data block.

The exact format and structure of the MFT in NTFS can vary depending on the version of the file system in use. However, the general structure remains the same, with the File Record Header, File Attribute List, and Data Runs being the main components of each MFT entry.

**Note: It’s important to note that accessing the MFT directly can be dangerous and potentially lead to file system corruption or data loss. Before attempting to access or modify the MFT, it’s recommended to perform operations on a backup of the MFT or back up important data beforehand.**


## Detailed Breakdown of MFT Fields

1. **$STANDARD_INFORMATION**
   - **Creation Time**: The date and time when the file or directory was created.
   - **Modification Time**: The date and time when the file or directory was last modified.
   - **Access Time**: The date and time when the file or directory was last accessed.
   - **Entry Modified Time**: The date and time when the MFT entry itself was last modified.
   - **Use Case**: These timestamps are vital for timeline analysis to determine the sequence of user actions and file usage.

2. **$FILE_NAME**
   - **File Name**: The name of the file or directory.
   - Parent Directory: The MFT record number of the directory in which the file resides.
   - **Additional Timestamps**: Similar to $STANDARD_INFORMATION, but specific to this attribute and sometimes used as a fallback.
   - **Use Case**: This attribute is used to confirm the integrity of file paths and names in the system, which is crucial for tracking user movements and detecting unauthorised changes.

3. **$DATA**
   - **Actual Data or Pointer**: Either the data itself for smaller files or a pointer to the data for larger files.
   - **Use Case**: Direct analysis of file contents and data recovery, especially important in cases involving data theft or unauthorized data manipulation.

4. **$LOGGED_UTILITY_STREAM**
   - **Transactional Data**: Holds data related to transactional NTFS (TxF), which logs temporary file state changes.
   - **Use Case**: Can be used to track changes made during a transaction, useful in cases of system crashes or unexpected shutdowns to determine interim states.

5. **$BITMAP**
   - **Cluster Allocation**: Maps which clusters are in use by the file.
   - **Use Case**: Useful for recovering deleted files or reconstructing file data from clusters not overwritten by new data.

6. **$SECURITY_DESCRIPTOR**
   - **Owner ID**: Identifies who owns the file.
   - **Permissions**: Details what permissions are attached to the file (who can read, write, execute, etc.).
   - **Audit Settings**: Specifies what operations (like access or changes) are logged by the system.
   - **Use Case**: Critical for determining access rights and detecting potential security breaches where permissions may have been altered.
  
7. **$VOLUME_INFORMATION** (specific to the MFT entry for the volume itself)
   - **Volume Serial Number**: Unique identifier for the volume.
   - **Flags**: System flags related to the volume, such as whether it’s dirty (improperly unmounted).
   - **Use Case**: Useful in multi-disk systems to link files and activities to specific volumes, essential in systems recovery and forensic analysis across multiple drives.
  
8. **\$INDEX_ROOT** and **\$INDEX_ALLOCATION**
   - **Index Entries**: Used in directories to index contained files for quick access.
   - **Use Case**: Forensically important for reconstructing directory structures and understanding how data was organized and accessed, particularly in complex investigations involving numerous files and directories.

## Timestamps
Created (0x10) is the Standard Information (SI) creation timestamp. This can be modified by user level processes, for example, timestomping. Created (0x30) is the FileName (FN) creation timestamp.

Timestamps of (FN) - behave differently from timestamps of (SI). These values don't change or all of the values change at once. However, rename and moved in a local volume are exceptions. These processes are inherited from (SI) value then set corresponding (FN) value. For more [NTFS Timestamps](http://www.kazamiya.net/en/NTFS_Timestamps).

## MFT Resident Files
Files that can be stored directly within the Master File Table (MFT) known as resident files. The size of this kind of files varies depending on the file, the system, and the amount of metadata stored in the MFT.

Generally, the more metadata associated with a file, the less space remains for storing the file's data itself within the MFT. While there is no strict upper limit, typically files smaller than approximately 900 bytes can be fully contained within their MFT record.


### References
- [GeeksForGeeks](https://www.geeksforgeeks.org/what-is-a-master-file-table/)
- [Kazamiya](http://www.kazamiya.net/en/NTFS_Timestamps)
- [Official Writeup BFT by Cyberjunkie & Sebh24 on HTB](BFT-Write-Up.pdf)