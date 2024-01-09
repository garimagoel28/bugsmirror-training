var moduleName = 'libfoo.so';

setTimeout(() => {
    Interceptor.attach(Module.findExportByName(moduleName, 'strncmp'),{
        onEnter:function(args){
            try{
                var str1 = Memory.readUtf8String(args[0]);
                var str2 = Memory.readUtf8String(args[1]);
                if(str1.includes("aaaaaaaaaaaaaaaaaaaaaaa") || str2.includes("aaaaaaaaaaaaaaaaaaaaaaa")){
                    console.log(str1,str2);
                }
            }
            catch (error) {
                console.error(error)
            }
        },
        onLeave:function(retval){

        }
    });

}, 3000);