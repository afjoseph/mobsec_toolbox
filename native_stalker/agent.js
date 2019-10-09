'use strict';

// Stolen from the amazing Awakened: <https://awakened1712.github.io/hacking/hacking-frida/>
function to_mem_address(mem_base, disk_base, disk_addr) {
  var offset = ptr(disk_addr).sub(disk_base);
  var result = ptr(mem_base).add(offset);
  return result;
}

function to_disk_address(mem_base, disk_base, mem_addr) {
  var offset = ptr(mem_addr).sub(mem_base);
  var result = ptr(disk_base).add(offset);
  return result;
}

function stalk_func(lib_name, addr, plt_start, plt_finish) {
  console.log(`[+] JS: stalk_func(): ${JSON.stringify(arguments)}`);

  let threads = {};
  const funcs = [ addr ]; // Only accept one function now
  const lib_base = Module.findBaseAddress(lib_name);
  console.log("[+] JS: Library base addr: " + lib_base);

  for (let i in funcs) {
    let mem_addr = to_mem_address(lib_base, '0x0', funcs[i]);
    console.log(`[+] JS: Hooking [${mem_addr}]...`);

    Interceptor.attach(mem_addr, {
      onEnter: function (args) {
        let tid = Process.getCurrentThreadId();
        if (tid in threads) {
          threads[tid]++;
          return;
        } else {
          threads[tid] = 0;
        }

        Stalker.follow(tid, {
          events: {
            call: true, // CALL instructions: yes please
            ret: false, // RET instructions: no thanks
            exec: false // all instructions: no thanks
          },
          onCallSummary: function (summary) {
            let log = [];
            for (i in summary) {
              let addr = to_disk_address(lib_base, '0x0', i);
              if (addr.compare(ptr(plt_start)) >= 0 && addr.compare(ptr(plt_finish)) <= 0)
                log.push(addr);
            }
            if (log.length !== 0) {
              send("calls:" + JSON.stringify(log));
            }
          }
        });
      },
      onLeave: function (retval) {
        let tid = Process.getCurrentThreadId();
        threads[tid]--;
        if (threads[tid] == 0) {
          Stalker.unfollow(tid);
          Stalker.garbageCollect();
        }
      }
    });
  }
}

rpc.exports = {
  loaders: function(lib_base, addr, plt_start, plt_finish) {
    console.log(`JS: loaders(): ${JSON.stringify(arguments)}`);
    Java.perform(function() {
      var system_def = Java.use('java.lang.System');
      var system_load_1 = system_def.load.overload('java.lang.String');
      var system_load_2 = system_def.loadLibrary.overload('java.lang.String');
      const Runtime = Java.use('java.lang.Runtime');
      const VMStack = Java.use('dalvik.system.VMStack');

      system_load_1.implementation = function(library) {
        console.log(`JS: Library [${library}] loaded with java.lang.String.load`);
        const loaded = Runtime.getRuntime().load0(VMStack.getCallingClassLoader(), library);
        stalk_func(lib_base, addr, plt_start, plt_finish);
        return loaded;
      };

      system_load_2.implementation = function(library) {
        console.log(`JS: Library [${library}] loaded with java.lang.String.loadLibrary`);
        const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
        stalk_func(lib_base, addr, plt_start, plt_finish);
        return loaded;
      };
    });
  }
};
