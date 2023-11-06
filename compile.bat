@ECHO OFF

rc resource.rc
cvtres /MACHINE:x64 /OUT:resource.o resource.res
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:implant.exe /SUBSYSTEM:WINDOWS /MACHINE:x64 resource.o
