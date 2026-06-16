#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

# Rebuilds helpers/ALGORITHMS.cache; see helpers/ALGORITHMS.cache/README.md.

set -ex

# force `sort` to do something consistent
export LC_ALL=C

find -name '*.rs' | sort | xargs grep 'impl.*Provider' > helpers/ALGORITHMS.cache/providers
find -name '*.rs' | sort | xargs grep 'impl.*Plumbing' > helpers/ALGORITHMS.cache/plumbing

find -name '*.rs' | sort | xargs awk '/enum.*Algorith/{flag=1;next}/}/{flag=0}flag{print FILENAME}flag{print}' > helpers/ALGORITHMS.cache/enum-algorithm-items
