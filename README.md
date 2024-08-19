# DRMBinViaOrdinalImports - Create Anti-Copy DRM Malware 

### Quick Links

[Maldev Academy Home](https://maldevacademy.com?ref=gh)
  
[Maldev Academy Syllabus](https://maldevacademy.com/syllabus?ref=gh)

[Maldev Academy Pricing](https://maldevacademy.com/pricing?ref=gh)

## Summary

This repository uses a technique to modify a program's Import Address Table (IAT) by replacing the imported function names with their corresponding ordinals, resulting in a binary that exclusively imports functions through ordinals. 

This method produces a binary that only operates on systems with the ordinal values for all the imported functions. This technique reduces the chances of the binary being successfully analyzed by sandbox systems due to the mismatch in ordinal values. This discrepancy causes the Windows Loader to either fail to locate the correct function address or retrieve an incorrect function, leading to the binary being broken in the sandbox environment. Lastly, this techniques makes it more challenging to reverse engineer the binary. 

This repository includes two projects:

### TechTestBuilder.exe

Reads a PE file from disk and writes an ordinal-imported functions version of it. The generated program will only run on a system where the imported functions have the same ordinal values as the system that generated it.

* Using the `TechTestBuilder.exe` program to generate `mimikatzDRM.exe`, which is `mimikatz.exe` but with ordinals-imported functions.
![DRM_1](https://github.com/user-attachments/assets/badca115-93bb-4519-8d63-7698f53a3a36)

</br>
</br>

* Running `mimikatzDRM.exe` on a different system than the one used to generate it, will throw the following error.
![DRM_2](https://github.com/user-attachments/assets/a813be44-7600-4b4f-a681-3f48b9796076)

</br>
</br>

### OrdinalDRMBin.exe

This project utilizes the DRN technique on itself when first executed. This means that this binary cannot be executed on other machines as easily. `OrdinalDRMBin.exe` applies the following steps:

1. Checks if the local program has any name-imported functions, if no, it will skip applying the IAT patch.

2. Read itself from the disk, and convert all of the name-imported functions to be ordinal-imported.

3. Delete itself from disk.

4. Write the new image where all the functions are imported by ordinal.

* The image below shows `OrdinalDRMBin.exe` without being executed. Notice the functions are imported by name.
![DRM 3](https://github.com/user-attachments/assets/6c94fa46-db56-48d8-a5de-1e9abbed4f57)

</br>
</br>

* The image below shows `OrdinalDRMBin.exe` after being executed. Notice the functions are now imported by their ordinals.
![DRM 4](https://github.com/user-attachments/assets/861f643c-23dc-4881-98a9-c58670a9cc87)

</br>

### Note

As mentioned, systems with the exact ordinal values for all of the imported functions of the generated implementation will be able to run the protected binary. However, the chances of this happening can be reduced by importing functions from different DLLs. The same approach used in [Module 80 - IAT Camouflage](https://maldevacademy.com/modules/80?view=blocks) module can be used for this purpose.


