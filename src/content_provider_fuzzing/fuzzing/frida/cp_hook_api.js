Java.perform(function () {
    var context_impl = Java.use('android.app.ContextImpl');

    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');

    context_impl.checkPermission
        .overload('java.lang.String', 'int', 'int')
        .implementation =
        function (permission, pid, uid) {
            if (uid === "<CP_FUZZER_UID>") {
                var stackTrace = stackTraceHere();
                send("DYNAMIC_ENFORCEMENT, " + permission + ", " + pid + ", " + uid + ", " + stackTrace);
            }

            return this.checkPermission(permission, pid, uid);
        };

    function stackTraceHere() {
        return Log.getStackTraceString(Exception.$new());
    }
});