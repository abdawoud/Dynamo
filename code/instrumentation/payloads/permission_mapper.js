
/***SETUP_CONFIG_GOES_HERE***/
SETUP_CONFIG_REPLACE_ME


// This is just a list for keeping record of instrumented methods
var simplyInstrument = [
    ['com.android.server.pm.PackageManagerService', 'checkUidPermission'],
    ['android.os.Binder', 'getCallingUid'],
    ['android.os.Binder', 'getCallingPid'],
    ['android.app.ContextImpl', 'enforceCallingOrSelfPermission'],
    ["android.app.AppOpsManager", "noteOp"],
    ["android.app.AppOpsManager", "checkOp"],
    ["android.app.AppOpsManager", "startOp"],
    ["android.app.AppOpsManager", "startOpNoThrow"],
    ["android.app.AppOpsManager", "finishOp"],
    ["android.app.AppOpsManager", "checkOpNoThrow"],
    ["android.app.AppOpsManager", "noteProxyOp"],
    ["android.app.AppOpsManager", "noteProxyOpNoThrow"],
    ["android.app.AppOpsManager", "checkAudioOp"],
    ["android.app.AppOpsManager", "checkAudioOpNoThrow"],
    ["android.app.AppOpsManager", "checkPackage"],
    ["com.android.server.AppOpsService|com.android.server.appop.AppOpsService", "noteOperation"],
    ["com.android.server.AppOpsService|com.android.server.appop.AppOpsService", "checkOperation"],
    ["com.android.server.AppOpsService|com.android.server.appop.AppOpsService", "startOperation"],
    ["com.android.server.AppOpsService|com.android.server.appop.AppOpsService", "finishOperation"],
    ["com.android.server.AppOpsService|com.android.server.appop.AppOpsService", "noteProxyOperation"],
    ["com.android.server.AppOpsService|com.android.server.appop.AppOpsService", "checkAudioOperation"],
    ["com.android.server.AppOpsService|com.android.server.appop.AppOpsService", "checkPackage"],
    ["com.android.server.pm.UserManagerService", "hasUserRestriction"],
];

var simplyLog = [
    //['android.os.Binder', 'clearCallingIdentity'],
    //['android.os.Binder', 'restoreCallingIdentity'],
    //['android.os.Binder', 'getCallingUserHandle'],
    //["android.os.UserHandle", "getUserId"],
    //["android.os.UserHandle", "getCallingUserId"],
    //["android.os.UserHandle", "getIdentifier"],
    ["android.os.UserHandle", "isSameApp"],
    ["android.os.Process", "myPid"]
];

var instrumentedList = [];

var blacklistedMethods = [
    "flushPendingCommands",
    "execTransact",
    "attachInterface",
    "toString",
    "transact",
    'wait',
    'clone',
    'equals',
    'linkToDeath',
    'unlinkToDeath',
    'notifyAll',
    'notify',
    "$init",
    "init",
    "<init>",
    "toString",
    "onTransact",
    "getContentResolver",
    "post",
    "constructor",
    "class",
    "getInterfaceDescriptor",
    "dump",
    "hashCode",
    "parseProcLine",
    "opToDefaultMode",
    "getUidStateLocked",
    "getOpsRawLocked",
    "getOpsLocked",
    "collectOps"
];

var instrumentedClasses = setup['instrumented_classes'];

const SYSTEM_SERVER = 'system_server';
const FUZZING_SERVICE = 'fuzzer.permission.uidchanger:InvokerService';

var fuzzedMethod = setup['method'];
var myPid = parseInt(setup['pid']);
var myUid = parseInt(setup['uid']);
var fakeUid = parseInt(setup['fake_uid']);
if (fakeUid === 1000000 || fakeUid === 10000000) {
    fakeUid = fakeUid + myUid
}
var fakePid = setup['fake_pid'];
var process_instrumented = setup['being_instrumented'];
var specialUids = [myUid, parseInt(setup['fake_uid']), fakeUid];
var fuzzingServiceName = "fuzzer.permission.uidchanger:InvokerService";

function isAlreadyInstrumented(clazzName, func) {
    for (var i = 0; i < simplyInstrument.length; i++) {
        if (simplyInstrument[i][0].split("|").indexOf(clazzName) > -1 && simplyInstrument[i][1] == func)
            return true;
    }

    for (var i = 0; i < instrumentedList.length; i++) {
        if (instrumentedList[i][0].split("|").indexOf(clazzName) > -1 && instrumentedList[i][1] == func)
            return true;
    }

    return false;
}

function argumentsAsArray(params) {
    if (params === undefined) {
        return [];
    }
    var args = [];
    for (var i = 0; i < params.length; i++) {
        args.push(params[i]);
    }
    return args;
}

function logMethodCallStack(that, func, ret, params) {
    try {
        var binder = Java.use("android.os.Binder");
        var uid = binder.getCallingUid();
        var b = false;
        for (var s in specialUids) {
            if (argumentsAsArray(params).indexOf(specialUids[s]) > -1) {
                b = true;
                break;
            }
        }
        if (b || specialUids.indexOf(uid) > -1 || func == "clearCallingIdentity" || func == "$init" || func == fuzzedMethod || func == "myPid") {
            var traces = []

            traces = Java.use("java.lang.Thread").currentThread().getStackTrace();

            var log = {
                "uid": uid,
                "call_ret": func + "(" + argumentsAsArray(params).join(", ") + ") = " + ret,
                "callstack": traces.join("\n")
            };

            if (log['callstack'].indexOf("."+fuzzedMethod+"(") > -1) {
                send({"processable": log});
            }
            return log;
        }
    } catch (e) {
        send("logMethodCallback: " + func + " -- " + ret + " : " + e)
        return null;
    }
}

function getMethodCallStack(that, func, params) {
    try {
        var binder = Java.use("android.os.Binder");
        var uid = binder.getCallingUid();
        if (specialUids.indexOf(uid) > -1) {
            var traces = Java.use("java.lang.Thread").currentThread().getStackTrace();
            return traces.join("\n");
        }
    } catch (e) {
        return null;
    }
}

function instrumentCheckUidPermission() {
    if (process_instrumented != SYSTEM_SERVER)
        return;
    var pms = Java.use("com.android.server.pm.PackageManagerService");
    var func = 'checkUidPermission'
    pms[func].implementation = function(){
        var perms = setup['permissions'];
        if (perms && perms.length > 0) {
            for (var k = 0; k < perms.length; k++) {
                if (arguments[0] === perms[k].split("::")[1]) {
                    logMethodCallStack(this, func, 0, arguments);
                    return 0; //Granted!
                }
            }
        }

        var ret = this[func].apply(this, arguments);
        logMethodCallStack(this, func, ret, arguments);
        return ret;
    }
}

function instrumentGetCallingUid() {
    var binder = Java.use("android.os.Binder");
    var func = 'getCallingUid';

    binder[func].implementation = function() {
        var old_uid = binder.getCallingUid();
        var callstack = getMethodCallStack(this, func, arguments);
        if (callstack && callstack.indexOf(fuzzedMethod) === -1) {
            return old_uid;
        }
        if (specialUids.indexOf(old_uid) > -1) {
            old_uid = fakeUid;
        }

        logMethodCallStack(this, func, old_uid, arguments);
        return old_uid;
    }

    /*
    var func = 'getCallingUid';
    Module.enumerateExports('libbinder.so', {
        onMatch: function(e) {
            if (e.name.indexOf(func) > -1) {
                Interceptor.attach(Module.findExportByName("libbinder.so", e.name), {
                    onEnter: function(args) {
                    },
                    onLeave: function(retval) {
                        if (specialUids.indexOf(parseInt(retval)) > -1) {
                            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
                            //console.log(e.name + ": " + fakeUid);
                            retval.replace(fakeUid);
                        }
                    }
                });
            }
        },
        onComplete: function() {}
    });
    */
}

function instrumentGetCallingPid() {
    var binder = Java.use("android.os.Binder");
    var func = 'getCallingPid';

    binder[func].implementation = function() {
        var binder = Java.use("android.os.Binder");
        var old_pid = binder.getCallingPid();

        if (fakePid == null || fakePid == -1) {
            logMethodCallStack(this, func, old_pid, arguments);
            return old_pid;
        }
        var callstack = getMethodCallStack(this, func, arguments);
        if (callstack && callstack.indexOf(fuzzedMethod) === -1) {
            return old_pid;
        }

        old_pid = parseInt(fakePid);
        logMethodCallStack(this, func, old_pid, arguments);
        return old_pid;
    }

    /*
    var func = 'getCallingPid';
    Module.enumerateExports('libbinder.so', {
        onMatch: function(e) {
            if (e.name.indexOf(func) > -1) {
                Interceptor.attach(Module.findExportByName("libbinder.so", e.name), {
                    onEnter: function(args) {
                    },
                    onLeave: function(retval) {
                        if (myPid == parseInt(retval)) {
                            //console.log(e.name + ": " + myPid);
                            retval.replace(fakePid)
                        }
                    }
                });
            }
        },
        onComplete: function() {}
    });
    */
}

function instrumentExceptionHandlers() {
    var exceptions = [
        "java.lang.IllegalArgumentException",
        "java.lang.NullPointerException",
        "java.lang.SecurityException",
        "java.lang.UnsupportedOperationException"
    ];

    if (process_instrumented != fuzzingServiceName) {
        /*
         * My implementation of the exception initialization, for some reason, stops the exception from being thrown.
         *  This causes a problem for API hosted on non system_server!
         */
        for (var i = 0; i < exceptions.length; i++) {
            // Instrumentation of constructors is blocked. Therefore, force instrument this!
            try {
                Java.use(exceptions[i])['$init'].overload('java.lang.String').implementation = function(str) {
                    logMethodCallStack(this, "$init", undefined, str);
                    return this['$init'](str);
                };
            } catch(e) {
                console.log(exceptions[i], e)
            }
        }
    }

    /*
     * We re-implement the ContextImpl.enforce inside enforceCallingOrSelfPermission to stop the system server
     *  from getting killed and throwing a DeadObjectException. Instead, we throw a SecurityException which is
     *  usually expected! We instrument enforceCallingOrSelfPermission because the "enforce" method is not visible
     *  for instrumentation!
     */
    var clazzName = "android.app.ContextImpl";
    var context = Java.use(clazzName);
    Object.keys(context).forEach(function(func) {
        if (typeof context[func] == 'function') {
            var overloads = getOverloads(context, func);
            overloads.forEach(function(entry) {
                if (func.indexOf('enforce') > -1 || func.indexOf('check') > -1) {
                    entry['overload'].implementation = function(){
                        var instrumented = isAlreadyInstrumented(clazzName, func);
                        if (!instrumented)
                            simplyInstrument.push([clazzName, func]);

                        var r = eval('this[func].overload(' + entry['parameters_str'] + ')').apply(this, arguments);
                        logMethodCallStack(this, func, r, arguments);
                        return r;
                    }
                }
            });
        }
    });

    //Hack for android 6 and others (unknown)!
    var binder = Java.use("android.os.Binder");
    var func = 'enforceCallingOrSelfPermission'
    context[func].implementation = function() {
        var binder = Java.use("android.os.Binder");
        var uid = binder.getCallingUid();
        if (arguments[0]) {
            var _arguments = [arguments[0]];
            var checkResult = this["checkCallingOrSelfPermission"].overload('java.lang.String').apply(this, _arguments);
            if (checkResult == -1) {
                var clazz = Java.use("java.lang.SecurityException");
                var obj = clazz.$new(uid + "::" + arguments[0]);
                throw obj;
            }
        }
        return;
    }
}

function instrumentUserRestrictions() {
    //@TODO this bypasses all user restrictions of all UIDs. Customize this!
    if (process_instrumented != SYSTEM_SERVER)
        return;
    var userMgrSrv = Java.use("com.android.server.pm.UserManagerService");
    var func = 'hasUserRestriction';

    var overloads = getOverloads(userMgrSrv, func);
    overloads.forEach(function(entry) {
        entry['overload'].implementation = function(){
            var restrictions = setup['user_restrictions'];
            if (restrictions && restrictions.length > 0) {
                for (var k = 0; k < restrictions.length; k++) {
                    if (arguments[0] === restrictions[k]) {
                        logMethodCallStack(this, func, false, arguments);
                        return false; //Granted!
                    }
                }
            }
            var r = eval('this[func].overload(' + entry['parameters_str'] + ')').apply(this, arguments);
            logMethodCallStack(this, func, r, arguments);
            return r;
        }
    });
}

function instrumentAppOpsMgrPermissions() {
    //@TODO this bypasses all user restrictions of all UIDs. Customize this!
    var appOpsMgr = Java.use("android.app.AppOpsManager");
    var funcs = [
        "noteOp",
        "checkOp",
        "startOp",
        "startOpNoThrow",
        "finishOp",
        "checkOpNoThrow",
        "noteProxyOp",
        "noteProxyOpNoThrow",
        "checkAudioOp",
        "checkAudioOpNoThrow",
        "checkPackage"
    ];
    funcs.forEach(function(func) {
        var overloads = getOverloads(appOpsMgr, func);
        overloads.forEach(function(entry) {
            entry['overload'].implementation = function(){
                var r = eval('this[func].overload(' + entry['parameters_str'] + ')').apply(this, arguments);
                if (r != undefined && /^\d+\.\d+$/.test(r)) {
                    logMethodCallStack(this, func, 0, arguments);
                    return 0; //MODE_ALLOWED
                }
                logMethodCallStack(this, func, r, arguments);
                return r;
            }
        });
    });
}

function instrumentAppOpsMgrSrvPermissions() {
    //@TODO this bypasses all user restrictions of all UIDs. Customize this!
    if (process_instrumented != SYSTEM_SERVER)
        return;

    var appOpsMgrSrv  = null;
    try {
        appOpsMgrSrv = Java.use("com.android.server.AppOpsService");
    } catch (e) {
        try {
            appOpsMgrSrv = Java.use("com.android.server.appop.AppOpsService");
        } catch (e) {
            return;
        }
    }
    var funcs = [
        "noteOperation",
        "checkOperation",
        "startOperation",
        "finishOperation",
        "noteProxyOperation",
        "checkAudioOperation",
        "checkPackage"
    ];
    funcs.forEach(function(func) {
        var overloads = getOverloads(appOpsMgrSrv, func);
        overloads.forEach(function(entry) {
            entry['overload'].implementation = function(){
                var r = eval('this[func].overload(' + entry['parameters_str'] + ')').apply(this, arguments);
                if (r != undefined && /^\d+\.\d+$/.test(r)) {
                    logMethodCallStack(this, func, 0, arguments);
                    return 0; //MODE_ALLOWED
                }
                logMethodCallStack(this, func, r, arguments);
                return r;
            }
        });
    });
}

//Prevent the system_server from crashing whenever there is an invalid binder interface sent to a system service
var module = Process.findModuleByName("libbinder.so");
Module.enumerateExportsSync(module.name).forEach(function (exp) {
    if (exp.name == "_ZNK7android6Parcel16enforceInterfaceERKNS_8String16EPNS_14IPCThreadStateE") {
        Interceptor.attach(ptr(exp.address), {
            onEnter: function(args) {
            },
            onLeave: function(retval) {
                retval.replace(1);
            }
        });
    }
});

function getParametersAsString(parameters) {
    var _parameters = parameters.map(parameter => "'" + parameter + "'");
    return _parameters.join(',');
}

function getOverloads(clazz, methodName) {
    var overloads = clazz[methodName].overloads;
    var result = [];
    if (!overloads)
        return result;
    overloads.map(function (overload) {
        var parameters = [];
        for (var i in overload['argumentTypes']) {
            parameters.push(overload['argumentTypes'][i].className);
        }

        var parameters_str = getParametersAsString(parameters);
        var overload = eval('clazz[methodName].overload(' + parameters_str + ')');
        var entry = {
            'class': clazz,
            'method': methodName,
            'overload': overload,
            'parameters': parameters,
            'parameters_str': parameters_str
        };
        result.push(entry);
    });

    return result;
}

function instrumentByLoggingMethods(list) {
    var cache = {};
    list.forEach(function(loggable) {
        try {
            var className = loggable[0];
            var methodName = loggable[1];
            if (!cache[className]) {
                cache[className] = Java.use(className);
            }

            var overloads = getOverloads(cache[className], methodName);
            if (isAlreadyInstrumented(className, methodName))
                return;
            else
                instrumentedList.push(loggable);

            overloads.forEach(function(entry) {
                //console.log(entry['class'].toString(), entry['method'], entry['parameters_str']);
                entry['overload'].implementation = function(){
                    var r = eval('this[methodName].overload(' + entry['parameters_str'] + ')').apply(this, arguments);
                    logMethodCallStack(this, methodName, r, arguments);
                    return r;
                }
            });
        } catch (e) {
            //console.log(e);
        }
    });
}

function isBlackListedMethod(methodName) {
    var blacklisted = blacklistedMethods.indexOf(methodName) > -1 || methodName.indexOf("-") > -1 ||
        methodName.indexOf("$") > -1 || methodName.indexOf("<init>") > -1;
    return blacklisted;
}

function getClassMethods(classObject) {
    var methods = [];
    for (var k in classObject) {
        methods.push(k);
    }
    return methods;
}

function getClassMethod(classObject, methodName) {
    for (var k in classObject) {
        if (k == methodName)
            return classObject[methodName];
    }
    return null;
}

/*
if (process_instrumented == SYSTEM_SERVER) {
    const mainThread = Process.enumerateThreads()[0];
    Stalker.follow({
        events: {
            call: true
        },
        onReceive: function (e) {
            console.log(JSON.stringify(Stalker.parse(e)));
        }
    });
}
*/

function getDeclaredMethodsReflection(clazz) {
    var clazzObject = Java.use('android.os.Binder');
    var methods = clazzObject.class.getDeclaredMethods();
    var modifiersClass = Java.use('java.lang.reflect.Modifier');
    for (var i = 0; i < methods.length; i++) {
        var modifiers = methods[i].getModifiers();
        var isNative = modifiersClass.isNative(modifiers);
        var isFastNative = methods[i].getAnnotation(Java.use('dalvik.annotation.optimization.FastNative').class);
        var isCriticalNative = methods[i].getAnnotation(Java.use('dalvik.annotation.optimization.CriticalNative').class);
        console.log(methods[i], isNative, Java.use('dalvik.annotation.optimization.FastNative').class, isFastNative, isCriticalNative, Java.use('dalvik.annotation.optimization.CriticalNative').class);
    }
    /*
    for (var i = 0; i < methods.length; i++) {
        if (methods[i].toString().indexOf('private ') > -1 && methods[i].toString().indexOf(className + "." + methodName + "(") > -1) {
            //methods[i].setAccessible(true);
            console.log(methods[i], typeof methods[i], methods[i].isAccessible());
            var parameters_ = methods[i].getParameters();
            for (var j = 0; j < parameters_.length; j++) {
                console.log(parameters_[j].getName())
            }
        }
    }
    */
}

function isNative(methods, methodName) {
    var modifiersClass = Java.use('java.lang.reflect.Modifier');
    for (var i = 0; i < methods.length; i++) {
        if (methods[i].getName() == methodName) {
            var modifiers = methods[i].getModifiers();
            var isNative = modifiersClass.isNative(modifiers);
            //console.log(methodName, isNative);
            return isNative;
        }
    }
    return false;
}

if (setup['service'] == 'vold' || setup['service'] == 'stats' || setup['service'] == 'installd' || setup['service'] == 'media.camera' || setup['service'] == 'incidentd' || setup['service'] == 'keystore' || setup['service'] == 'stats') {
    Module.enumerateExports('libbinder.so', {
        onMatch: function(e) {
            if (e.name.indexOf('getCallingUid') > -1) {
                Interceptor.attach(Module.findExportByName("libbinder.so", e.name), {
                    onEnter: function(args) {
                    },
                    onLeave: function(retval) {
                        if (parseInt(retval) == parseInt(myUid)) {
                            retval.replace(fakeUid);
                        }
                    }
                });
            }

            if (e.name.indexOf('checkPermission') > -1) {
                Interceptor.attach(Module.findExportByName("libbinder.so", e.name), {
                    onEnter: function(args) {
                        var permission = args[0].readPointer().readUtf16String();
                        var _pid = args[1].toInt32();
                        var _uid = args[2].toInt32();
                        var log = {
                            "uid": myUid,
                            "call_ret": e.name + "(" + permission + ", " + _pid + ", " + _uid + ") = 0",
                            "callstack": []
                        };

                        send({"processable": log});
                    },
                    onLeave: function(retval) {
                        retval.replace(1);
                    }
                });
            }

            if (e.name.indexOf('checkCallingPermission') > -1) {
                Interceptor.attach(Module.findExportByName("libbinder.so", e.name), {
                    onEnter: function(args) {
                        var permission = args[0].readPointer().readUtf16String();
                        var log = {
                            "uid": -1,
                            "call_ret": e.name + "(" + permission + ") = 0",
                            "callstack": []
                        };

                        send({"processable": log});
                    },
                    onLeave: function(retval) {
                        retval.replace(1);
                    }
                });
            }
        },
        onComplete: function() {}
    });

    if (process_instrumented == SYSTEM_SERVER) {
        Java.perform(function () {
            var pms = Java.use("com.android.server.pm.PackageManagerService");
            var func = 'checkUidPermission'
            pms[func].implementation = function(){
                return 0;
            }
        });
    }
} else {
    Java.perform(function () {
        var faking_system_or_root = [1000, 0].indexOf(fakeUid) > -1;
        var is_activity_service = setup['service'] == 'activity';

        if (instrumentedClasses.length > 0 && process_instrumented != FUZZING_SERVICE) {
            instrumentByLoggingMethods([[instrumentedClasses[0], setup['method']]])
        }

        //if (!faking_system_or_root && !is_activity_service) {
        //    instrumentedClasses.forEach(function(clazz) {
        //        try {
        //            var clazzObject = Java.use(clazz);
        //            var methods = clazzObject.class.getMethods();
        //            getClassMethods(clazzObject).forEach(function(func) {
        //                if (!isBlackListedMethod(func) && !isNative(methods, func)) {
        //                    instrumentByLoggingMethods([[clazz, func]])
        //                }
        //            });
        //        } catch (e) {}
        //    });
        //}

        // Grant the new permission(s)
        instrumentCheckUidPermission();

        // Fake the calling UID
        instrumentGetCallingUid();

        // Fake the calling PID
        instrumentGetCallingPid();

        // Catch exceptions (especially the SecurityException) and handle the issue related to the catching logic!
        instrumentExceptionHandlers();

        // Bypass user's restrictions
        instrumentUserRestrictions();

        // Grant all AppOps permissions -> manager's side
        instrumentAppOpsMgrPermissions();

        // Grant all AppOps permissions -> service's side
        instrumentAppOpsMgrSrvPermissions();

        // Instrument all methods under simplyLog to print the callstack of each API

        //if (!faking_system_or_root && !is_activity_service) {
        //    instrumentByLoggingMethods(simplyLog);
        //}

        Java.use("android.os.UserHandle").isSameApp.implementation = function(){
            var r = this.isSameApp.apply(this, arguments);
            logMethodCallStack(this, "isSameApp", r, arguments);
            return r;
        }

        Java.use("android.os.Process").myPid.implementation = function(){
            var r = this.myPid.apply(this, arguments);
            logMethodCallStack(this, "myPid", r, arguments);
            return r;
        }
    });
}