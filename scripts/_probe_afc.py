import asyncio
import inspect

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.afc import AfcService


async def main():
    ld = await create_using_usbmux()
    print(f"lockdown type: {type(ld).__name__}")
    afc = AfcService(ld)
    print(f"afc type: {type(afc).__name__}")
    print(f"afc.connect attr type: {type(getattr(afc, 'connect', None))}")
    methods = ['connect', 'listdir', 'stat', 'fopen', 'fread', 'fclose',
               'walk', 'pull', 'get_file_contents', 'dirlist', 'os_stat']
    for m in methods:
        attr = getattr(afc, m, None)
        if attr is None:
            print(f"  {m:20s} : MISSING")
        elif inspect.iscoroutinefunction(attr):
            print(f"  {m:20s} : async")
        elif callable(attr):
            print(f"  {m:20s} : sync")
        else:
            print(f"  {m:20s} : {type(attr).__name__}")
    # Try the actual call
    try:
        result = afc.listdir("/")
        if inspect.iscoroutine(result):
            print("  listdir('/') returned coroutine -> awaiting...")
            result = await result
        print(f"  listdir('/') => {result[:5]}...")
    except Exception as e:
        print(f"  listdir('/') failed: {e}")


asyncio.run(main())
