console.log("hello")
Java.perform(function () {
    var MainActivity = Java.use('com.example.loginscreen.MainActivity');

    MainActivity.onCreate.overload('android.os.Bundle').implementation = function (bundle) {
        // Call the original onCreate method
        this.onCreate(bundle);

        // Access UI elements after the onCreate method is called
        var context = this.getApplicationContext();
        var resources = context.getResources();

        // Replace these with the correct resource IDs (integer values)
        var editTextUsernameId = resources.getIdentifier('editTextUsername', 'id', context.getPackageName());
        var editTextPasswordId = resources.getIdentifier('editTextPassword', 'id', context.getPackageName());
        var buttonLoginId = resources.getIdentifier('buttonLogin', 'id', context.getPackageName());

        var editTextUsername = this.findViewById(editTextUsernameId);
        var editTextPassword = this.findViewById(editTextPasswordId);
        var buttonLogin = this.findViewById(buttonLoginId);

        buttonLogin.setOnClickListener.implementation = function (view) {
            var username = editTextUsername.getText().toString();
            var password = editTextPassword.getText().toString();

            console.log('Username: ', username);
            console.log('Password: ', password);

            // Call the original onClick method
            this.onClick(view);
        };
    };
});
