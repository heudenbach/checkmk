#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H. Eudenbach in the year 2021 in progress

def splitDisk(line):
	result = []
	res1 = line.split("/", 1)
	result.append(res1[0])
	res2 = res1[1].split(" ", 1)
	result.append(res2[0])
	result.append(res2[1])
	return result

print(splitDisk("ssd/base-206-disk-0 210GiB2.80GiB"))
print(splitDisk("ssd/base-206-disk-1 220GiB2.80GiB"))
print(splitDisk("ssd/base-206-disk-2 230GiB2.80GiB"))
print(splitDisk("ssd/base-206-disk-3 240GiB2.80GiB"))






'test4'
#test
