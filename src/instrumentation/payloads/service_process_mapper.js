/*
 This is copied from https://github.com/dessertlab/fantastic_beasts
 All credit goes to the creators of Chizpurfle fuzzer for this implementation
*/

"use strict";

function Discover()
{
  var f1;
  var f2;
  var f3;

  Module.enumerateExports("libselinux.so",{
    onMatch: function(exp){
      if (exp.name === "selabel_lookup"){
        f1 = exp;
      }
      if (exp.name === "getpidcon"){
        f2 = exp;
      }
      if (exp.name === "selinux_check_access"){
        f3 = exp;
      }
    },
    onComplete: function(){}
  });

  Interceptor.attach(ptr(f1.address),{
    onEnter: function(args){
      send({'key': 'name', 'value': Memory.readCString(args[2])});
      recv('detach', function(value){
        console.log("detaching...");
        Interceptor.detachAll();
      });
    }
  });
  Interceptor.attach(ptr(f2.address),{
    onEnter: function(args){
      send({'key': 'pid', 'value': args[0].toInt32()});
    }
  });
  Interceptor.attach(ptr(f3.address),{
    onEnter: function(args){
      send({'key': 'selinux_type', 'value': Memory.readCString(args[0])});
      send({'key': 'perm', 'value': Memory.readCString(args[3])});
    }
  });
}

Discover();