# go-execute-assembly

## Details

This project is mainly a Go port of [metasploit-execute-assembly](https://github.com/b4rtik/metasploit-execute-assembly) from [@b4rtik](https://github.com/b4rtik/).

It starts a `notepad.exe` process, use reflective DLL injection to inject the .NET CLR hosting DLL, as well as the assembly to run and its arguments.

If you don't trust the DLL, you can build your own version from [here](https://github.com/b4rtik/metasploit-execute-assembly/tree/master/HostingCLR_inject).
The code will determine the offset for the RefelctiveLoader automatically.

## Usage

Compile, then  run with:
```
PS> execute-assembly.exe PATH_TO_ASSEMBLY PATH_TO_HOSTING_DLL
```

The [main.go](https://github.com/lesnuages/go-execute-assembly/blob/master/main.go) is an exemple, feel free to adapt to your needs.
