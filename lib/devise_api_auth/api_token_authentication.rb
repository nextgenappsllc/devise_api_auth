require 'devise'
module ApiTokenAuthentication
	  
	  class ApiTokenAuthenticatable < Devise::Strategies::Authenticatable
	    def valid?
	      _token_matcher.valid?
	    end

	    def authenticate!
	      if _token_matcher.match! && !_user.nil? && _validate_user
	        success!(_user)
	      else
	        fail('Failed api token authentication')
	      end
	    end

	    private
	    def _validate_user
	    	return true unless _config_options.include?(:model_auth_validation_method)
	    	_user.send(_config_options[:model_auth_validation_method].to_sym)
	    end

	    def _token_utils
	    	DeviseApiAuth::TokenUtils::SecureCredentials.new(headers: request.headers)
	    end

	    def _requested_time
	    	_secure_credentials[:date]
	    end

	    def _user_token
	    	_secure_credentials[:token]
	    end

	    def _user_id
	    	_secure_credentials[_config_options[:model_id_attribute].to_sym]
	    end

	    def _secure_credentials
	    	@_secure_credentials ||= _token_utils.get_header_credentials
	    end

	    def _token_matcher
	    	@_token_matcher ||= DeviseApiAuth::TokenUtils::DateTokenMatcher.new(strings: [_requested_time, DeviseApiAuth::TokenUtils.generate_user_token(_user_id)], date: _requested_time, token: _user_token)
	    end

	    def _user
	      @_user ||= begin
	      	return if _user_id.blank?
	      	if _config_options[:model_find_method].nil?
	      		mapping.to.where(_config_options[:model_id_attribute].to_sym => _user_id).first
	      	else
	      		mapping.to.send(_config_options[:model_find_method].to_sym, _user_id)
	      	end
	      	
	      end
	    end

	    def _config_options
	    	DeviseApiAuth::Config.options
	    end

	  end


	end

	Warden::Strategies.add(:api_token_authentication, ApiTokenAuthentication::ApiTokenAuthenticatable)
	Devise.add_module :api_token_authentication, strategy: true


