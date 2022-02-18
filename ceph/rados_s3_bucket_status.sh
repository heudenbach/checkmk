#!/bin/bash

# H.Eudenbach in 2022 - holger@eude.rocks
# Local check for checkmk 2.0p19, ceph 14
#
# place on rados gateway at -> /usr/lib/check_mk_agent/plugins/
# make executeable -> chmod +x 
# test with check_mk_agent, will appear under <<<local>>>
# switch to checkmk, go to rados gateway host, do service discovery, add service - done.
# if no quota is set, status will always be 0 - 0, works only for Buckets of 1GB or higher!

# change this to the bucket you want to watch
bucket=BUCKETNAME

# getting sizes
radosgw_s3_size_actual=$(
radosgw-admin bucket stats --bucket=$bucket | grep '"size":' | sed 's/            \"size\"\:\ //g' | sed 's/.$//'
)

radosgw_s3_size_max=$(
radosgw-admin bucket stats --bucket=$bucket | grep '"max\_size":' | sed 's/\"max\_size\"\:\ //g' | sed 's/.$//'
)

# calculating remaining space
radosgw_s3_size_remaining=$(($radosgw_s3_size_max - $radosgw_s3_size_actual))

# calculating to GB - edit for other formats
act=$(($radosgw_s3_size_actual / 1024 / 1024 / 1024))       #Actual Usage of Bucket
max=$(($radosgw_s3_size_max / 1024 / 1024 / 1024))          #Maximum Usage of Bucket (Quota)
rem=$(($radosgw_s3_size_remaining / 1024 / 1024 / 1024))    #Remaining Usage of Bucket

# calculating warn / crit
maxten=$(($max / 10))   #warning at 10% of Maximum Usage
maxtwen=$(($max / 20))  #critical 5% of Maximum Usage

# actual check ok/crit/warn
if (($rem >= $maxten)); then
echo "0 \"Bucket Size $bucket\" "$bucket"_usage=$rem;$maxten;$maxtwen;0;$max" $rem GB of $max GB remaining

elif (($rem < $maxtwen)); then
echo "2 \"Bucket Size $bucket\" "$bucket"_usage=$rem;$maxten;$maxtwen;0;$max" $rem GB of $max GB remaining

elif (($rem <= $maxten)); then
echo "1 \"Bucket Size $bucket\" "$bucket"_usage=$rem;$maxten;$maxtwen;0;$max" $rem GB of $max GB remaining

fi