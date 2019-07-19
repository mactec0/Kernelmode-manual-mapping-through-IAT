## Manual mapping x64 without creating any threads

Instead of using CreateRemoteThread or typical thread hijacking methods(e.g. GetThreadContext), 
this mapper injects into code flow through import table. 
Address of function is overwritten with stub address, it is later restored after calling the stub.
It supports interacting with the process by handle or kernel driver.
Injecting with a driver allows you to execute code inside protected processes. 

#### Usage:
```cpp
mmap mapper(INJECTION_TYPE::KERNEL); // or INJECTION_TYPE::USERMODE

if (!mapper.attach_to_process("example_process.exe"))
	return 1;

if (!mapper.load_dll("example_dll.dll"))
	return 1;

if (!mapper.inject())
	return 1;
```
![](https://i.imgur.com/cKyFRrb.png)

</br></br>

#### Credits
- [teosek](https://github.com/teosek "teosek") //usermode_proc class, import walking
- Daquas //testing