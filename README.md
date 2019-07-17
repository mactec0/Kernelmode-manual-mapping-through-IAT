## Manual mapping x64 without usage of CreateRemoteThread

Instead of using CreateRemoteThread or typical thread hijacking methods(e.g. GetThreadContext), 
this mapper injects into code flow through import table. 
Address of function is overwritten with stub address, it is later restored after calling the stub.

#### Usage:
```cpp
c_mmap mapper;
	
if (!mapper.attach_to_process("notepad.exe"))
	return 1;

if (!mapper.load_dll("example_dll.dll"))
	return 1;

if (!mapper.inject())
	return 1;
```
![](https://i.imgur.com/EQHFMJh.png)

</br></br>

#### Credits
- [teosek](https://github.com/teosek "teosek")