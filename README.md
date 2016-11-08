## devise_api_auth

# Rails implementation

## Add the gem to your gemfile.

```ruby
# Gemfile
gem 'devise_api_auth'
```
## Configure the gem in an initializer.

Two different secrets and an encryption key are required. To generate the secrets I would use:
```console 
$ rake secret 
```
And for the key provide an MD5 hash of a passphrase like:
```ruby
# irb
require 'digest'
Digest::MD5.hexdigest('passphrase')
```
You should not keep the secrets and key in version control so I recommend using environmental variables or .gitignore

### Available options:

#### Required

* **app_token:** The mobile app is expected to have this embeded as well and it is used for csrf
* **encryption_key:** The server and mobile app uses this to encrypt and decryptthe credentials
* **user_salt:** The server uses this salt to create a hash for the user token from a user.

#### Optional
The defaults are shown below in the example code.

* **header_iv:** The name of the initialization vector field in the header
* **header_credentials:** The name of credentials field in header 
* **param_iv:** The name of the initialization vector field in the parameters
* **param_credentials:** The name of credentials field in parameters 
* **model_id_attribute:** The the field that is used to search for the user model in authentication
* **model_find_method:** The name of the class method that will be used to find the model for authentication
* **model_auth_validation_method:** The name of the instance method to run on the model during authentication

```ruby
# app/config/initializers/devise_api_auth.rb
require 'devise_api_auth'
DeviseApiAuth::Config.configure do |options|

  # required
  options[:app_token] = 'generated secret'
  options[:encryption_key] = 'generated MD5 hash of passphrase'
  options[:user_salt] = 'other generated secret'
  
  # optional
  options[:header_iv] = 'x-app-iv'
  options[:header_credentials] = 'x-app-credentials'
  options[:param_iv] = '_iv'
  options[:param_credentials] = '_credentials'
  options[:model_id_attribute] = 'id'
  options[:model_find_method] = :class_method_name # default: nil
  options[:model_auth_validation_method] = :instance_method_name # default: nil

end
```

## Add to controller
```ruby
require 'devise_api_auth/date_csrf'
class ApplicationController < ActionController::Base
  include DeviseApiAuth::DateCSRF
  #...
end
```

## Include in model
```ruby
require 'devise'
require 'devise_api_auth'
class User < ActiveRecord::Base

  # Make sure :api_token_authentication is included
  devise :database_authenticatable, :rememberable, :trackable, :validatable, :api_token_authentication
  
  # Optional methods
  
  # Make sure to set the attribute :model_find_method in the config options hash to the name of this method.
  # This method receives value the user identifier specified in the credentials passed in the header
  # Return model instance if successful
  def self.model_find_method(id)
    return if id.nil?
    User.find_by(id: id)
  end
  
  # Make sure to set the attribute :model_auth_validation_method in the config options hash to the name of this method.
  def model_auth_validation_method
    !disabled?
  end
  
  # Fake method for demonstration logic
  def disabled?
    false
  end

end
```

# Mobile app implementation

## iOS (Swift)



