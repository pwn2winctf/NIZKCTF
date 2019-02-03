#!/bin/bash

echo "Organization name (As in github. Ex. pwn2winctf): "
read org
echo "CTF name (ex. Pwn2Win 2019): "
read name
echo "CTF id/repo name (ex. 2019): "
read ctf
echo "Flag format example (ex. CTF-BR{fl4g}): "
read flag

sed -i 1,2d example-README.*.md
sed -i 's/pwn2winctf/'$org'/Ig' example-README.*.md
sed -i 's/NIZKCTF\ example\ CTF/'"$name"'/Ig' example-README.*.md
sed -i 's/nizkctf/'$ctf'/Ig' example-README.*.md
sed -i 's/CTF-BR{flag123}/'"$flag"'/Ig' example-README.*.md

mv {example-,}README.en.md
mv {example-,}README.pt.md

echo "Done!"
