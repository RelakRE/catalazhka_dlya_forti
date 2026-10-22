#!/bin/zsh
emulate -L zsh
task_folder="${0:A:h}"
/usr/bin/python3 "$task_folder/route_probe.py" --recover
task_result=$?
print
read -r '?Нажмите Enter, чтобы закрыть окно: '
exit "$task_result"
