# dll_injector

### don't use this in any games that don't have a dysfunctional anti cheat, you will get banned. (LoadLibraryW)

## Usage
config parsing follows a strict line-by-line order. rearranging params will cause the injector to fail.

```
inject_wait=2000         ; wait before injecting each DLL (ms)
init_wait=6000           ; wait after starting the target executable(ms)
path\to\program.exe      ; target executable
path\to\1.dll            ; DLLs to inject in line sequence
path\to\2.dll
path\to\3.dll
```

## License

dll_injector uses the WTFPL license. See the [LICENSE](LICENSE.md) file if direly necessary.
