Java.perform(function(){
    var klass = Java.use("@ORKESTRA_PARAM_JCLASS@")
    klass.@ORKESTRA_PARAM_METHOD@.overload(@ORKESTRA_PARAM_OVERLOADS@).implementation = function(@ORKESTRA_PARAM_ARGS@){
        var result = this.@ORKESTRA_PARAM_METHOD@(@ORKESTRA_PARAM_ARGS@)

        send({
            name: "@ORKESTRA_PARAM_JCLASS@.@ORKESTRA_PARAM_METHOD@",
            args: [@ORKESTRA_PARAM_ARGS@],
            retval: result
        })
    
        return result
    }
})