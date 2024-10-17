#!/bin/bash

   # Get the kernel version
   KERNEL_VERSION=$(uname -r)

   # Extract major, minor, and patch versions
   MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
   MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
   PATCH=$(echo $KERNEL_VERSION | cut -d. -f3 | cut -d- -f1)

   # Calculate LINUX_VERSION_CODE
   VERSION_CODE=$((($MAJOR << 16) + ($MINOR << 8) + $PATCH))

   # Create a temporary file with LINUX_VERSION_CODE definition
   echo "#define LINUX_VERSION_CODE $VERSION_CODE" > temp_version.h

   # Concatenate the temporary file with the original vmlinux.h
   cat temp_version.h vmlinux.h > vmlinux_with_version.h

   # Replace the original vmlinux.h
   mv vmlinux_with_version.h vmlinux.h

   # Clean up
   rm temp_version.h

   echo "Updated vmlinux.h with LINUX_VERSION_CODE"