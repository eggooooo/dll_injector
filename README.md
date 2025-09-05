# dll_injector

## Usage
config parsing follows a strict line-by-line order. rearranging params will cause the injector to fail.

```
inject_wait=2000         ; wait before injecting each DLL (ms)
init_wait=6000           ; wait after starting the target executable(ms)
path\to\program.exe      ; target executable
DLL1.dll                 ; DLLs to inject in line sequence
DLL2.dll
DLL3.dll
```

## License

dll_injector uses the WTFPL license. See the [LICENSE](LICENSE.md) file if direly necessary.