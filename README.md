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

The library I use to handle encryption in iOS is called [CyptoSwift](https://github.com/krzyzanowskim/CryptoSwift). I wrote the following extensions to assit with the serialization and encryption of the credentials. Create a .swift file in your project and paste the following code:

```swift
// DeviseApiAuthExtensions.swift
import CryptoSwift


extension String {
    /**
     Encrypts the string with the given 32 bit key.
     
     If you would like to use a passphrase instead of the key then use the md5 hash of the passphrase to ensure it is 32 bit like in the following example.
     ````
     let key = "passphrase".md5()
     let encryptionResult = "encrypt me!".AES256Encrypt(key: key)
     ````
     
     - Parameter key: The key to use for encryption. **Must be 32 bits in length.**
     
     - Returns: A tuple containing the hex string values on the initialization vector and the encrypted data.
     */
    func AES256Encrypt(key:String)->(iv:String, encrypted:String?){
        let _key = key.utf8.map{$0}
        let _iv = AES.randomIV(AES.blockSize)
        var t:(iv:String, encrypted:String?) = (_iv.toHexString(), nil)
        guard _key.count == 32, let aes = try? AES(key: _key, iv: _iv), let encrypted = try? aes.encrypt(Array(self.utf8)) else {return t}
        t.encrypted = encrypted.toHexString()
        return t
    }
    
    /**
     Decrypts the string with the given 32 bit key and initialization vector.
     
     If you would like to use a passphrase instead of the key then use the md5 hash of the passphrase to ensure it is 32 bit like in the following example.
     ````
     let key = "passphrase".md5()
     let encryptionResult = "encrypt me!".AES256Encrypt(key: key)
     let decrypted = encryptionResult.encrypted?.AES256Decrypt(key: key, iv: encryptionResult.iv)
     ````
     
     - Parameter key: The key to use for encryption. **Must be 32 bits in length.**
     
     - Parameter iv: The initialization vector used to encrypt the data as a hex string.
     
     - Returns: A decrypted string if successful
     */
    func AES256Decrypt(key:String, iv:String) -> String?{
        let _key = key.utf8.map{$0}
        let _iv = iv.convertFromHex()
        guard _key.count == 32, let aes = try? AES(key: _key, iv: _iv), let decrypted = try? aes.decrypt(self.convertFromHex()) else {return nil}
        return String(data: Data(decrypted), encoding: .utf8)
    }
    
    /**
     Converts the string into an array of numbers corresponding to the hex value of character pairs.
     
     So the string "ff00" would get broken up into pairs so "ff" and "00" and then converted to numbers. 
     The returned array would be [255, 0].
     
     - Returns: An array of 8 bit unsigned integers.
     */
    func convertFromHex() -> [UInt8]{
        var values:[UInt8] = []
        var chars = characters
        var pair = ""
        while let char = chars.popFirst() {
            pair = "\(pair)\(char)"
            if pair.characters.count > 1 {
                if let value = UInt8(pair, radix: 16){values.append(value)}
                pair = ""
            }
        }
        return values
    }
    
}

extension Data {
    /**
     Shortcut to convert data into a string.
     
     Encoding is optional and the default is UTF8.
     
     - Returns: A string if successful
     */
    func toString(encoding: String.Encoding = .utf8) -> String? {
        return String(data: self, encoding: encoding)
    }
}

extension Dictionary {
    /**
     Shortcut to convert a dictionary into JSON data.
     
     - Returns: Data if successful
     */
    func toJsonData() -> Data? {
        return try? JSONSerialization.data(withJSONObject: self, options: .init(rawValue: 0))
    }
    
    /**
     Shortcut to convert a dictionary into a JSON string.
     
     It calls toJsonData()?.toString() on a dictionary.
     
     - Returns: A string if successful
     */
    func toJsonString() -> String? {
        return toJsonData()?.toString()
    }
}
```



