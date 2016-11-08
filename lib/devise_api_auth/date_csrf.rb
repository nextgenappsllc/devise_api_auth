module DeviseApiAuth
		module DateCSRF

	  def verified_request?
	    super || app_token_verified?
	  end

	  def app_token_verified?
	    verify_app_token
	  end

	  def verify_app_token
	    TokenUtils::DateTokenMatcher.new(strings: [_requested_time,DeviseApiAuth::Config.options[:app_token]],date: _requested_time, token: _date_token).match!
	  end

	  private
	  def _token_utils
	  	@_token_utils ||= TokenUtils::SecureCredentials.new(headers: request.headers, params: params)
	  end

	  def _requested_time
	    _secure_header_credentials[:date]
	  end

	  def _date_token
	    _secure_param_credentials[:token]
	  end

	  def _secure_header_credentials
	  	_token_utils.get_header_credentials
	  end

	  def _secure_param_credentials
	  	_token_utils.get_param_credentials
	  end


	end
end