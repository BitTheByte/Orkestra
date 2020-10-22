Java.perform(function(){
    var className = "@ORKESTRA_PARAM_0@"
    var jClass = Java.use(className);

    var classDescription = {
        class: className,
        body:{
            methods: jClass.class.getDeclaredMethods().map(function(instance){
                instance.setAccessible(true)
                return {
                    header: instance.toString(),
                    name:   instance.getName(),
                    params: instance.getParameterTypes().toString().replace("class ","").split(",").filter(function(param){
                        return param != ""
                    })
                }
            }),
            fields: jClass.class.getDeclaredFields().filter(function(instance) {
                return instance.toString().includes(className)
            }).map(function(instance){
                instance.setAccessible(true)
                return instance.toString()
            })
        }
    }
    
    send(classDescription)

    console.log(JSON.stringify(classDescription, null, 2))
})