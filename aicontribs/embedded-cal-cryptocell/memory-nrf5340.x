/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss */

/* nRF5340 application core, secure image without bootloader or TF-M */
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 1024K
  RAM : ORIGIN = 0x20000000, LENGTH = 512K
}
