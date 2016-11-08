module DeviseApiAuth
	module Config
		extend self
		attr_reader :options
		def configure
			yield self.options
		end
		def options
			@options ||= {
				header_iv: 'x-app-iv',
				header_credentials: 'x-app-credentials',
				param_iv: '_iv',
				param_credentials: '_credentials',
				model_id_attribute: 'id'
			}
		end
	end
end


# DeviseApiAuth::Config.configure do |options|
# 	options[:app_token] # mobile app has this as well and it is used for csrf
# 	options[:encryption_key] # mobile app uses this to encrypt and decrypt
# 	options[:user_salt] # rails uses this to create a user token from a user

# 	# optional
# 	options[:header_iv] # name of the iv field in the header
# 	options[:header_credentials] # name of credentials field in header 
# 	options[:param_iv] # name of the iv field in the parameters
# 	options[:param_credentials] # name of credentials field in parameters 
# 	options[:model_id_attribute] # the field that is used to search for the user model in authentication
#   options[:model_find_method] # passes the user identifier to a class method on the model to act as initialization and verification. Return an instance of your user model on succes and nil upon failure.
# 	options[:model_auth_validation_method] # name of method to run on the model during authentication

# end